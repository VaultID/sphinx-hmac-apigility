<?php

namespace RB\Sphinx\Hmac\Zend;

use Zend\ModuleManager\Feature\AutoloaderProviderInterface;
use Zend\ModuleManager\Feature\ConfigProviderInterface;
use Zend\Mvc\MvcEvent;

class Module implements AutoloaderProviderInterface, ConfigProviderInterface {
	public function getAutoloaderConfig() {
		return array (
				'Zend\Loader\ClassMapAutoloader' => array (
						__DIR__ . '/autoload_classmap.php' 
				),
				'Zend\Loader\StandardAutoloader' => array (
						'namespaces' => array (
								__NAMESPACE__ => __DIR__ . '/src/' 
						) 
				) 
		);
	}
	public function getConfig() {
		return include __DIR__ . '/config/module.config.php';
	}
	
	/**
	 * {@inheritDoc}
	 */
	public function onBootstrap($e) {
		$app = $e->getApplication ();
		$services = $app->getServiceManager ();
		$em = $app->getEventManager ();
		
		/**
		 *
		 * @todo : Ajustar prioridade do Listener (precisa ser antes do processamento de ACL's)
		 */
		$em->attach ( MvcEvent::EVENT_ROUTE, $services->get ( 'RB\Sphinx\Hmac\Zend\Server\HMACListener' ), - 500 );
	}
}