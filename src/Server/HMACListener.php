<?php

namespace RB\Sphinx\Hmac\Zend\Server;

use Zend\Mvc\MvcEvent;
use Zend\Authentication\Result;
use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Zend\Server\HMACHeaderAdapter;
use RB\Sphinx\Hmac\Zend\Server\HMACSessionHeaderAdapter;
use RB\Sphinx\Hmac\Exception\HMACException;
use RB\Sphinx\Hmac\Exception\HMACAdapterInterruptException;

class HMACListener {
	
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
	 * Listener para EVENT_ROUTE
	 *
	 * @param MvcEvent $e        	
	 */
	public function __invoke(MvcEvent $e) {
		$request = $e->getRequest ();
		
		/**
		 * Só tratar requisições HTTP(S)
		 */
		if (! method_exists ( $request, 'getHeaders' )) {
			return;
		}
		
		/**
		 * Verificar configuração de autenticação HMAC
		 * $this->selector será definido a partir da configuração
		 */
		try {
			if (! $this->_checkConfig ( $e ))
				return;
			
			/**
			 * Executar autenticação com Adapter definido
			 */
			$adapter = __NAMESPACE__ . '\\' . $this->adapterClass;
			if ($adapter::canHandle ( $e )) {
				$this->adapter = new $adapter ();
				/**
				 * Autenticar a requisição
				 */
				$result = $this->adapter->authenticate ( $e, $this->selector );
			} else {
				$result = new Result ( Result::FAILURE, null, array (
						'HMAC Authentication required' 
				) );
			}
		} catch ( HMACAdapterInterruptException $exception ) {
			/**
			 * Se o Adapter interromper a requisição, devolver imediatamente a resposta
			 *
			 * TARGET: Zend\Mvc\Controller\AbstractActionController
			 */
			return $e->getTarget ()->getResponse ();
		} catch ( HMACException $exception ) {
			$result = new Result ( Result::FAILURE, null, array (
					'HMAC ERROR: ' . $exception->getMessage () 
			) );
		}
		
		/**
		 * Verificar resultado da autenticação HMAC
		 */
		if (! $result->isValid ()) {
			
			/**
			 * TARGET: Zend\Mvc\Controller\AbstractActionController
			 */
			$response = $e->getTarget ()->getResponse ();
			
			/**
			 * PREPARAR RESPOSTA DE ERRO
			 */
			$response->getHeaders ()->addHeaderLine ( 'Content-Type', 'application/problem+json' );
			
			$resposta = array (
					'type' => 'https://github.com/reinaldoborges/rb-sphinx-hmac-zf2/wiki',
					'title' => 'Unauthorized',
					'status' => 401,
					'detail' => implode ( "\n", $result->getMessages () ),
					'instance' => $request->getUriString () 
			);
			
			/**
			 * Informar descrição do HMAC na mensagem de erro
			 */
			if ($this->adapter !== NULL) {
				$description = $this->adapter->getHmacDescription ();
				if ($description !== NULL) {
					$resposta ['hmac'] = $description;
					$resposta ['version'] = $this->adapter->getVersion();
				}
			}
			
			$response->setContent ( json_encode ( $resposta ) );
			$response->setStatusCode ( 401 );
			
			return $response;
		}
		
		/**
		 * Registrar identidade autenticada para que fique acessível ao Controller
		 */
		$e->setParam ( 'RBSphinxHmacAdapterIdentity', $result->getIdentity () );
		
		
		/**
		 * Registrar Listener para inserir assinatura HMAC, caso o Adapter esteja definido
		 */
		if ($this->adapter !== NULL) {
			$target = $e->getTarget ();
			if (! $target || ! is_object ( $target ) || ! method_exists ( $target, 'getEventManager' )) {
				return;
			}
			
			$events = $target->getEventManager ();
			$events->attach ( 'finish', [ 
					$this,
					'onFinish' 
			], 1000 );
			
			/**
			 * Registrar Adapter para disponibilizar ao Controller via Plugin
			 */
			$e->setParam ( 'RBSphinxHmacAdapter', $this->adapter );
		}
	}
	
	/**
	 * Checa configuração de autenticação HMAC para Controller/Action
	 *
	 * @param MvcEvent $e        	
	 * @return boolean - Aplicar autenticação HMAC
	 */
	protected function _checkConfig(MvcEvent $e) {
		/**
		 * Se configuração não existir para o Controller, retornar silenciosamente
		 */
		$app = $e->getApplication ();
		$services = $app->getServiceManager ();
		
		$config = $services->get ( 'Config' );
		
		if (! isset ( $config ['rb_sphinx_hmac_server'] ) || ! isset ( $config ['rb_sphinx_hmac_server'] ['controllers'] )) {
			return false;
		}
		
		/**
		 * Identificação do Controller/Action
		 */
		$params = $e->getRouteMatch ()->getParams ();
		$controller = $params['controller'];

		/**
		 * Apigility REST não tem Action
		 */
		if( isset( $params['action'] ) )
			$action = $params['action'];
		else
			$action = '';
		
		
		/**
		 * Se Controller não está na lista, retornar sem autenticação HMAC
		 */
		if (! array_key_exists ( $controller, $config ['rb_sphinx_hmac_server'] ['controllers'] )) {
			return false;
		}
		
		/**
		 * Verificar se há filtro de actions na configuração do controller.
		 */
		if (isset ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] ) && is_array ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] )) {
			
			/**
			 * Se não existir a chave, ou se o valor for FALSE ou NULL, não tratar este Action com o HMAC
			 */
			if (! array_key_exists ( $action, $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] ) || $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] === FALSE || $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] === NULL) {
				return false;
			}
		}
		
		/**
		 * Selector é obrigatório
		 */
		$selector = $this->_getActionConfig ( $config, $controller, $action, 'selector' );
		if ($selector === NULL || $selector === '') {
			throw new HMACException ( 'HMAC SELECTOR não definido para Controller ' . $controller );
		}
		
		/**
		 * Verificar se Selector está definido
		 */
		if (! isset ( $config ['rb_sphinx_hmac_server'] ['selectors'] ) || ! is_array ( $config ['rb_sphinx_hmac_server'] ['selectors'] ) || ! array_key_exists ( $selector, $config ['rb_sphinx_hmac_server'] ['selectors'] )) {
			throw new HMACException ( 'HMAC SELECTOR não definido na configuração: ' . $selector );
		}
		
		/**
		 * Verificar mapeamento do Selector para Serviço da AbstractFactory
		 */
		$selectorMap = $config ['rb_sphinx_hmac_server'] ['selectors'] [$selector];
		if ($selectorMap === NULL || $selectorMap === '') {
			throw new HMACException ( 'HMAC SELECTOR não mapeado para ' . $selector );
		}
		$this->selector = $selectorMap;
		
		/**
		 * Adapter é obrigatório
		 */
		$adapter = $this->_getActionConfig ( $config, $controller, $action, 'adapter' );
		if ($adapter === NULL || $adapter === '') {
			throw new HMACException ( 'HMAC ADAPTER não definido para Controller ' . $controller );
		}
		
		/**
		 * Verificar se Adapter está definido
		 */
		if (class_exists ( $adapter )) {
			throw new HMACException ( 'HMAC ADAPTER não definido: ' . $adapter );
		}
		$this->adapterClass = $adapter;
		
		return true;
	}
	
	/**
	 * Recuperar configuração
	 */
	protected function _getActionConfig($config, $controller, $action, $configKey) {
		$value = NULL;
		
		/**
		 * Verificar se há filtro de actions na configuração do controller.
		 */
		if (isset ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] ) && is_array ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] )) {
			
			/**
			 * Verificar se há $configKey específico para a action
			 */
			if (isset ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] ) && is_array ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] )) {
				if (array_key_exists ( $configKey, $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] )) {
					$value = $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] ['actions'] [$action] [$configKey];
				}
			}
		}
		
		/**
		 * Verificar $configKey específico para o controller
		 */
		if ($value === NULL && isset ( $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] [$configKey] )) {
			$value = $config ['rb_sphinx_hmac_server'] ['controllers'] [$controller] [$configKey];
		}
		
		/**
		 * Verificar $configKey padrão para todos os controller's
		 */
		if ($value === NULL && isset ( $config ['rb_sphinx_hmac_server'] ['default_' . $configKey] )) {
			$value = $config ['rb_sphinx_hmac_server'] ['default_' . $configKey];
		}
		
		return $value;
	}
	
	/**
	 * Listener para EVENT_FINISH acrescentar assinatura HMAC na resposta
	 *
	 * @param MvcEvent $e        	
	 * @throws HMACException
	 */
	public function onFinish(MvcEvent $e) {
		if ($this->adapter === NULL)
			throw new HMACException ( 'Adapter HMAC não inicializado' );
		
		$this->adapter->signResponse ( $e );
	}
}
