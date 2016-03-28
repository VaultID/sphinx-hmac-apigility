<?php

namespace RB\Sphinx\Hmac\Zend\Client;

use Zend\Http\Client;
use Zend\Http\Request;

use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Zend\Server\HMACHeaderAdapter;


class HMACHttpClient extends Client {
	
	/**
	 * 
	 * @var HMAC
	 */
	protected $hmac = null;
	
	
	/**
	 * (non-PHPdoc)
	 * @see \Zend\Http\Client::send()
	 */
	public function send(Request $request = null) {
		
		if( $this->hmac === null )
			throw new \Exception('HMAC é necessário para a requisição');
		
		if( $request === null ) {
			$request = $this->getRequest();
		}
		
		/**
		 * Dados a assinar (versão 1 do protocolo)
		 */
		$assinarDados =
			$request->getMethod()                     // método
			. $request->getUriString()                // URI
			. $request->getContent();                 // content
		
		/**
		 * Assinatura HMAC
		 */
		$assinaturaHmac = $this->hmac->getHmac( $assinarDados );
		
		/**
		 * Header de autenticação (protocolo versão 1)
		*/
		$headerAuth = HMACHeaderAdapter::VERSION    // versão do protocolo
			. ':' . $this->hmac->getKeyId()         // ID da chave/aplicação/cliente
			. ':' . $this->hmac->getNonceValue()    // nonce
			. ':' . $assinaturaHmac;                // HMAC Hash
		
		$request->getHeaders()->addHeaderLine(HMACHeaderAdapter::HEADER_NAME, $headerAuth);
		
		/**
		 * Enviar requisição
		 */
		return parent::send($request);
	}
	
	
	/**
	 * 
	 * @param HMAC $hmac
	 * @return \RB\Sphinx\Hmac\Zend\Client\HMACHttpClient
	 */
	public function setHmac(HMAC $hmac) {
		$this->hmac = $hmac;
		return $this;
	}
	
	/**
	 * 
	 * @return \RB\Sphinx\Hmac\HMAC
	 */
	public function getHmac() {
		return $this->hmac;
	}
	
}