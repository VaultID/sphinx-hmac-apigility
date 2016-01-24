<?php

namespace RB\Sphinx\Hmac\Zend\Server\Plugin;

use Zend\Mvc\Controller\Plugin\AbstractPlugin;
use Zend\Mvc\Controller\AbstractController;

class HMACAdapter extends AbstractPlugin {
	/**
	 * Retorna o Adapter HMAC utilizado no HMAC
	 *
	 * @param string $param        	
	 * @param mixed $default        	
	 * @return mixed
	 */
	public function __invoke() {
		$controller = $this->getController ();
		if ($controller instanceof AbstractController) {
			$adapter = $controller->getEvent ()->getParam ( 'RBSphinxHmacAdapter', NULL );
			if ($adapter !== NULL)
				return $adapter;
		}
		
		return NULL;
	}
}
