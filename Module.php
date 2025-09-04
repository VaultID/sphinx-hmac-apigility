<?php

namespace RB\Sphinx\Hmac\Zend;

use Laminas\ModuleManager\Feature\AutoloaderProviderInterface;
use Laminas\ModuleManager\Feature\ConfigProviderInterface;
use Laminas\Mvc\MvcEvent;
use Laminas\Mvc\ModuleRouteListener;

class Module implements AutoloaderProviderInterface, ConfigProviderInterface {
  public function getAutoloaderConfig() {
    return [
        'Laminas\Loader\ClassMapAutoloader' => [
            __DIR__ . '/autoload_classmap.php' 
        ],
        'Laminas\Loader\StandardAutoloader' => [
            'namespaces' => [
                __NAMESPACE__ => __DIR__ . '/src/' 
            ] 
        ] 
    ];
  }
  public function getConfig() {
    return include __DIR__ . '/config/module.config.php';
  }
  
  /**
   * {@inheritDoc}
   */
  public function onBootstrap($e) {
    $app = $e->getApplication();
    $services = $app->getServiceManager();
    $em = $app->getEventManager();
    
    /**
     * Baixa prioridade, para avaliar necessidade de autenticação HMAC após todas as operações de rota
     */
    $em->attach(MvcEvent::EVENT_DISPATCH, $services->get('RB\Sphinx\Hmac\Zend\Server\HMACListener'), 10);
    
    /**
     * Baixa prioridade, para acrescentar assinatura HMAC após todas as operações na resposta
     */
    $moduleRouteListener = new ModuleRouteListener();
    $moduleRouteListener->attach($em);
    $em->attach(
        MvcEvent::EVENT_FINISH,
        array($services->get('RB\Sphinx\Hmac\Zend\Server\HMACListener'), 'onFinish'),
        10
    );
  }
}