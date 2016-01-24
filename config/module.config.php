<?php
return array (
		'service_manager' => array (
				'invokables' => array (
						'RB\Sphinx\Hmac\Zend\Server\HMACListener' => 'RB\Sphinx\Hmac\Zend\Server\HMACListener' 
				) 
		),
		'controller_plugins' => array (
				'invokables' => array (
						'HMACKeyId' => 'RB\Sphinx\Hmac\Zend\Server\Plugin\HMACKeyId',
						'HMACAdapter' => 'RB\Sphinx\Hmac\Zend\Server\Plugin\HMACAdapter' 
				) 
		) 
);