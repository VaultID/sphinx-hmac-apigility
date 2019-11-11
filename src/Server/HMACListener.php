<?php

namespace RB\Sphinx\Hmac\Zend\Server;

use Zend\Mvc\MvcEvent;
use Zend\Http\Request;
use Zend\Authentication\Result;
use Zend\ServiceManager\ServiceLocatorInterface;
use Zend\EventManager\SharedEventManagerInterface;
use ZF\Rest\ResourceEvent;
use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Zend\Server\HMACHeaderAdapter;
use RB\Sphinx\Hmac\Zend\Server\HMACSessionHeaderAdapter;
use RB\Sphinx\Hmac\Exception\HMACException;
use RB\Sphinx\Hmac\Exception\HMACAdapterInterruptException;

class HMACListener {

    protected $_debugCount = 0;

    protected function _debug($msg) {
        $this->_debugCount++;
        //file_put_contents('/tmp/rest.log', $this->_debugCount . ': ' . $msg . "\n", FILE_APPEND);
    }

    /**
     *
     * @var HMACAbstractAdapter
     */
    protected $adapter = NULL;

    /**
     *
     * @var string
     */
    protected $adapterClass = NULL;

    /**
     * Seletor do serviço da AbstratcFactory que irá instanciar o HMAC
     *
     * @var string
     */
    protected $selector = NULL;

    /**
     * 
     * @var array
     */
    protected $restParams = array();

    /**
     * Listener para EVENT_ROUTE
     *
     * @param MvcEvent $e        	
     */
    public function __invoke(MvcEvent $e) {
        $this->_debug('__invoke');

        /**
         * Só tratar requisições HTTP(S)
         */
        $request = $e->getRequest();
        if (!method_exists($request, 'getHeaders')) {
            return;
        }

        /**
         * Guardar objetos necessários para validação APIGILITY REST
         */
        $app = $e->getApplication();
        $serviceManager = $app->getServiceManager();
        $config = $serviceManager->get('Config');

        $this->restParams['config'] = $config;
        $this->restParams['request'] = $e->getRequest();
        $this->restParams['serviceManager'] = $serviceManager;

        /**
         * Verificar configuração de autenticação HMAC
         * $this->selector será definido a partir da configuração
         */
        try {
            /**
             * Se não requer autenticação HMAC, retornar silenciosamente
             */
            if (!$this->_checkConfig($e))
                return;

            /**
             * Executar autenticação com Adapter definido na configuração
             */
            $adapter = __NAMESPACE__ . '\\' . $this->adapterClass;
            if ($adapter::canHandle($request)) {
                /**
                 * Autenticar a requisição
                 */
                $this->adapter = new $adapter();

                /**
                 * Registrar Adapter para disponibilizar ao Controller via Plugin
                 */
                $e->setParam('RBSphinxHmacAdapter', $this->adapter);
                $result = $this->adapter->authenticate($request, $this->selector, $e->getApplication()->getServiceManager(), $e);
            } else {
                $result = new Result(Result::FAILURE, null, array(
                    'HMAC Authentication required'
                ));
            }
        } catch (HMACAdapterInterruptException $exception) {
            /**
             * Se o Adapter interromper a requisição, devolver imediatamente a resposta
             *
             * TARGET: Zend\Mvc\Controller\AbstractActionController
             */
            return $e->getTarget()->getResponse();
        } catch (HMACException $exception) {
            $result = new Result(Result::FAILURE, null, array(
                'HMAC ERROR: ' . $exception->getMessage()
            ));
        }

        /**
         * Verificar resultado da autenticação HMAC
         */
        if (!$result->isValid()) {

            /**
             * TARGET: Zend\Mvc\Controller\AbstractActionController
             */
            $response = $e->getTarget()->getResponse();

            /**
             * PREPARAR RESPOSTA DE ERRO
             */
            $response->getHeaders()->addHeaderLine('Content-Type', 'application/problem+json');

            $resposta = array(
                'type' => 'https://github.com/reinaldoborges/rb-sphinx-hmac-zf2/wiki',
                'title' => 'Unauthorized',
                'status' => 401,
                'detail' => implode("\n", $result->getMessages()),
                'instance' => $request->getUriString()
            );

            /**
             * Informar descrição do HMAC na mensagem de erro
             */
            if ($this->adapter !== NULL) {
                $description = $this->adapter->getHmacDescription();
                if ($description !== NULL) {
                    $resposta['hmac'] = $description;
                    $resposta['version'] = $this->adapter->getVersion();
                }
            }

            $response->setContent(json_encode($resposta));
            $response->setStatusCode(401);

            return $response;
        }

        /**
         * Registrar identidade autenticada para que fique acessível ao Controller
         */
        $e->setParam('RBSphinxHmacAdapterIdentity', $result->getIdentity());
    }

    /**
     * Checa configuração de autenticação HMAC para Controller/Action
     *
     * @param MvcEvent $e        	
     * @return boolean - Aplicar autenticação HMAC
     */
    protected function _checkConfig(MvcEvent $e, $config = null) {
        $this->_debug('_checkConfig');

        /**
         * Recuperar configuração salva em __invoke()
         */
        if ($config == null) {
            $config = $this->restParams['config'];
        }

        /**
         * Se configuração não existir para o Controller, retornar silenciosamente
         */
        if (!isset($config['rb_sphinx_hmac_server']) || !isset($config['rb_sphinx_hmac_server']['controllers'])) {
            return false;
        }

        $requestProps = $this->getRequestProperties($e, $this->restParams['request'], $config);

        /**
         * Se Controller não está na lista, retornar sem autenticação HMAC
         */
        if (!array_key_exists($requestProps['controller'], $config['rb_sphinx_hmac_server']['controllers'])) {
            return false;
        }

        /**
         * Selector é obrigatório
         */
        $selector = $this->_getActionConfig('selector', $requestProps, $config);
        if ($selector === NULL || $selector === '') {
            throw new HMACException('HMAC SELECTOR não definido para Controller ' . $controller);
        } elseif ($selector === false) {
            return false;
        }

        /**
         * Verificar se Selector está definido
         */
        if (!isset($config['rb_sphinx_hmac_server']['selectors']) || !is_array($config['rb_sphinx_hmac_server']['selectors']) || !array_key_exists($selector, $config['rb_sphinx_hmac_server']['selectors'])) {
            throw new HMACException('HMAC SELECTOR não definido na configuração: ' . $selector);
        }

        /**
         * Verificar mapeamento do Selector para Serviço da AbstractFactory
         */
        $selectorMap = $config['rb_sphinx_hmac_server']['selectors'][$selector];
        if ($selectorMap === NULL || $selectorMap === '') {
            throw new HMACException('HMAC SELECTOR não mapeado para ' . $selector);
        }
        $this->selector = $selectorMap;

        /**
         * Adapter é obrigatório
         */
        $adapter = $this->_getActionConfig('adapter', $requestProps, $config);
        if ($adapter === NULL || $adapter === '') {
            throw new HMACException('HMAC ADAPTER não definido para Controller ' . $controller);
        }

        /**
         * Verificar se Adapter está definido
         */
        if (class_exists($adapter)) {
            throw new HMACException('HMAC ADAPTER não definido: ' . $adapter);
        }
        $this->adapterClass = $adapter;

        return true;
    }

    /**
     * Obtém as propriedades da requisição.
     * 
     * @return Array [
     * 	'controller' => {controller da rota solicitada},
     *  'plurality' => {'entity'|'collection'}, 
     * 	'method' => {'GET'|'POST'|'PUT'|'PATCH'|'DELETE'}
     * ]
     */
    protected function getRequestProperties($event, $request, $config) {
        $routeMatch = $event->getRouteMatch();
        $routeParams = $routeMatch->getParams();
        $routeIdName = $config['zf-rest'][$routeParams['controller']]['route_identifier_name'];
        $plurality = array_key_exists($routeIdName, $routeParams) ? 'entity' : 'collection';
        
        return[
            'controller' => $routeParams['controller'],
            'plurality' => $plurality,
            'method' => $request->getMethod()
        ];
    }

    /**
     * Obtém a configuração para a chave informada.
     * 
     * @param String $configKey Chave da ação {selector|adapter}
     * @param Array $requestProps Propriedades da requisição  ['controller' => {controller da rota solicitada}, 'plurality' => {'entity'|'collection'}, 'method' => {'GET'|'POST'|'PUT'|'PATCH'|'DELETE'}]
     * @param Array $config Configuração geral
     * 
     * @return Array|null Configuração da chave informada.
     */
    protected function _getActionConfig($configKey, $requestProps, $config) {
        $controller = $requestProps['controller'];
        $plurality = $requestProps['plurality'];
        $method = $requestProps['method'];

        $innerConfig = $config['rb_sphinx_hmac_server']['controllers'];

        /** Obtém a configuração default para $configKey */
        if (isset($config['rb_sphinx_hmac_server']['default_' . $configKey])) {
            $defaultConfig = $config['rb_sphinx_hmac_server']['default_' . $configKey];
        }

        /** Obtém a configuração para todas as requisições da collection */
        if (array_key_exists($configKey, $innerConfig)) {
            return $innerConfig[$configKey];
        }
        /** Obtém a configuração da pluralidade do controller {collection | entity} */
        if (!array_key_exists($plurality, $innerConfig = $innerConfig[$controller])) {
            return $defaultConfig; // Retorna default caso não haja
        } else if ($innerConfig == false) {
            return false; // Retorna sem aplicar HMAC
        } else if (array_key_exists($configKey, $innerConfig = $innerConfig[$plurality])) {
            return $innerConfig[$configKey]; // Retorna a configuração para todos os métodos {GET, POST...} da pluralidade
        }
        /** Obtém a configuração do método {GET,POST...} na pluralidade do controller */
        if(!array_key_exists($method, $innerConfig = $innerConfig)) {
            return $defaultConfig; // Retorna default caso não haja
        } else if ($innerConfig == false) {
            return false; // Retorna sem aplicar HMAC
        } else if (array_key_exists($configKey, $innerConfig = $innerConfig[$method])) {
            return $innerConfig[$configKey]; // Retorna a configuração específica para o método da pluralidade
        }
        return $defaultConfig;
    }

    /**
     * Listener para EVENT_FINISH acrescentar assinatura HMAC na resposta
     *
     * @param MvcEvent $e        	
     * @throws HMACException
     */
    public function onFinish(MvcEvent $e) {
        $this->_debug('onFinish');

        /**
         * Verificar no evento a necessidade de resposta com assinatura HMAC
         */
        if ($this->adapter !== NULL) {
            $this->_debug(' Sign');
            $this->adapter->signResponse($e);
        }
    }
}