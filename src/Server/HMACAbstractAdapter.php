<?php

namespace RB\Sphinx\Hmac\Zend\Server;

use Zend\Mvc\MvcEvent;
use Zend\Http\Request;

abstract class HMACAbstractAdapter {
	
	/**
	 * Versão atual do Adapter
	 *
	 * @var number
	 */
	const VERSION = - 1;
	
	/**
	 *
	 * @var \RB\Sphinx\Hmac\HMAC
	 */
	protected $hmac;
	
	/**
	 *
	 * @param MvcEvent $e        	
	 * @return boolean
	 */
	public static function canHandle(Request $request) {
		return false;
	}
	
	/**
	 *
	 * @param MvcEvent $e        	
	 * @param string $selector        	
	 */
	public abstract function authenticate(Request $request, $selector, $services, MvcEvent $e = null);
	
	/**
	 *
	 * @param MvcEvent $e        	
	 * @param string $selector        	
	 */
	public abstract function signResponse(MvcEvent $e);
	
	/**
	 *
	 * @return string
	 */
	public function getHmacDescription() {
		if ($this->hmac !== NULL)
			return $this->hmac->getDescription ();
		return NULL;
	}
	
	/**
	 * Utiliza o ServiceManager para instanciar o HMAC
	 */
	public function _initHmac($services, $selector) {
		if ($this->hmac === NULL) {
			$this->hmac = $services->get ( $selector );
		}
	}
	
	/**
	 *
	 * @return string
	 */
	public function getVersion() {
		return static::VERSION;
	}
	
	/**
	 * Assinar mensagem
	 *
	 * @param string $data        	
	 * @return string|NULL
	 */
	public function sign($data) {
		if ($this->hmac !== NULL)
			return $this->hmac->getHmac ( $data );
		return NULL;
	}
}