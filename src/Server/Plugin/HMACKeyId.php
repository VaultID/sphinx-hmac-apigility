<?php

namespace RB\Sphinx\Hmac\Zend\Server\Plugin;

use RB\Sphinx\Hmac\Zend\Server\HMACServerHelper;

use Laminas\Mvc\Controller\Plugin\AbstractPlugin;
use Laminas\Mvc\Controller\AbstractController;

class HMACKeyId extends AbstractPlugin {
	/**
	 * Retorna o KeyID autenticado no HMAC
	 */
	public function __invoke() {
		if ($this->getController() instanceof AbstractController) 
			return HMACServerHelper::getHmacKeyId($this->getController()->getEvent());
		
		return NULL;
	}
}
