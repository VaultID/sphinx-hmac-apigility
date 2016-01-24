<?php

namespace RB\Sphinx\Hmac\Zend\Server\Plugin;

use Zend\Mvc\Controller\Plugin\AbstractPlugin;
use Zend\Mvc\Controller\AbstractController;

class HMACKeyId extends AbstractPlugin {
	/**
	 * Retorna o KeyID autenticado no HMAC
	 *
	 * @param string $param        	
	 * @param mixed $default        	
	 * @return mixed
	 */
	public function __invoke() {
		$controller = $this->getController ();
		if ($controller instanceof AbstractController) {
			$keyId = $controller->getEvent ()->getParam ( 'RBSphinxHmacAdapterIdentity', NULL );
			if ($keyId !== NULL)
				return $keyId ['keyid'];
		}
		
		return NULL;
	}
}
