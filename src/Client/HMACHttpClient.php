<?php

namespace RB\Sphinx\Hmac\Zend\Client;

use Zend\Http\Client;
use Zend\Http\Request;
use Zend\Http\Exception\RuntimeException;

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
	 * 
	 * Acrescenta HEADER para autenticação HMAC antes de enviar a requisição.
	 * Verificar HEADER HMAC na resposta antes de devolver a resposta.
	 * 
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
		$response = parent::send($request);
		
		/**
		 * Recuperar header com assinatura HMAC
		 */
		$header = $response->getHeaders()->get(HMACHeaderAdapter::HEADER_NAME);
		
		if( $header === false )
			throw new RuntimeException('HMAC não está presente na resposta');
		
		$header = $header->getFieldValue();
		
		$headerData = explode(':', $header);
		if( count($headerData) != 2 )
			throw new RuntimeException('HMAC da resposta é inválido (header incorreto)');
		
		$versao = $headerData[0];
		$assinatura = $headerData[1];
		
		/**
		 * Verificar versão do protocolo
		*/
		if( $versao != HMACHeaderAdapter::VERSION )
			throw new RuntimeException('HMAC da resposta é inválido (versão incorreta)');
		
		/**
		 * Verificar assinatura
		 */
		$this->hmac->validate( $response->getBody(), $assinatura);
		
		return $response;
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