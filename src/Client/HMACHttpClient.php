<?php

namespace RB\Sphinx\Hmac\Zend\Client;

use Zend\Http\Client;
use Zend\Http\Request;
use Zend\Http\Response;
use Zend\Http\Exception\RuntimeException;

use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\Zend\Server\HMACHeaderAdapter;
use RB\Sphinx\Hmac\HMACSession;
use RB\Sphinx\Hmac\Zend\Server\HMACUriAdapter;

class HMACHttpClient extends Client {
	
	const HMAC_HEADER = 0;
	const HMAC_URI = 1;
	
	protected $hmacMode = self::HMAC_HEADER;
	
	/**
	 * 
	 * @var HMAC
	 */
	protected $hmac = null;
	
	/**
	 * Contador de mensagens enviadas
	 * @var int
	 */
	protected $hmacContador = 0;
	
	/**
	 * Indicar se sessão já foi iniciada
	 * @var bool
	 */
	protected $hmacSession = false;
	
	/**
	 * Iniciar sessão HMAC
	 * @param Request $request
	 * @throws RuntimeException
	 */
	protected function _startSession( Request $request ) {
		/**
		 * Clonar requisição inicial para aproveitar configurações
		 */
		$sessionRequest = clone $request;
		
		/**
		 * Início de sessão com método OPTIONS (sem BODY)
		 */
		$sessionRequest->setMethod('OPTIONS');
		$sessionRequest->setContent('');
		
		/**
		 * Assinatura de início de sessão (igual assinatura sem sessão)
		 */
		$this->_sign($sessionRequest);
		
		/**
		 * Requisitar início de sessão
		 */
		$response = parent::send($sessionRequest);
		
		/**
		 * Recuperar header com assinatura HMAC
		 */
		$header = $response->getHeaders()->get(HMACHeaderAdapter::HEADER_NAME);
		
		if( $header === false )
			throw new RuntimeException('HMAC não está presente na resposta');
		
		$header = $header->getFieldValue();
		
		$headerData = explode(':', $header);
		if( count($headerData) != 3 )
			throw new RuntimeException('HMAC da resposta é inválido (header incorreto)');
		
		$versao = $headerData[0];
		$nonce2 = $headerData[1];
		$assinatura = $headerData[2];
		
		/**
		 * Verificar versão do protocolo
		*/
		if( $versao != HMACHeaderAdapter::VERSION )
			throw new RuntimeException('HMAC da resposta é inválido (versão incorreta)');
		
		/**
		 * Informar Nonce2 enviado pelo servidor
		 */
		$this->hmac->setNonce2Value($nonce2);
		
		/**
		 * Verificar assinatura do NONCE2 enviado pelo servidor
		*/
		$this->hmac->validate( $nonce2, $assinatura, HMACSession::SESSION_RESPONSE );
		
		/**
		 * Indicar início da sessão após validar resposta
		 */
		$this->hmac->startSession();
		$this->hmacSession = true;
		
	}
	
	/**
	 * Assinar requisição (sem sessão)
	 * @param Request $request
	 * @throws RuntimeException
	 */
	protected function _sign( Request $request ) {
		if( $this->hmacContador > 0 )
			throw new RuntimeException('HMAC sem sessão só pode enviar uma mensagem');
		
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
		$assinaturaHmac = $this->hmac->getHmac( $assinarDados, HMACSession::SESSION_REQUEST );
		
		/**
		 * Header de autenticação (protocolo versão 1)
		*/
		$headerAuth = HMACHeaderAdapter::VERSION    // versão do protocolo
			. ':' . $this->hmac->getKeyId()         // ID da chave/aplicação/cliente
			. ':' . $this->hmac->getNonceValue()    // nonce
			. ':' . $assinaturaHmac;                // HMAC Hash
		
		$request->getHeaders()->addHeaderLine(HMACHeaderAdapter::HEADER_NAME, $headerAuth);
		
	}

	/**
	 * Assinar URI (sem sessão)
	 * @param Request $request
	 * @throws RuntimeException
	 */
	protected function _signUri( Request $request ) {
		if( $this->hmacContador > 0 )
			throw new RuntimeException('HMAC sem sessão só pode enviar uma mensagem');
		
		/**
		 * Dados a assinar (versão 1 do protocolo)
		 */
		$assinarDados = $request->getUriString();   // URI

		/**
		 * Assinatura HMAC
		 */
		$assinaturaHmac = $this->hmac->getHmac( $assinarDados, HMACSession::SESSION_REQUEST );
		
		/**
		 * Parâmetro de autenticação (protocolo versão 1)
		*/
		$authParam = HMACHeaderAdapter::VERSION    // versão do protocolo
			. ':' . $this->hmac->getKeyId()         // ID da chave/aplicação/cliente
			. ':' . $this->hmac->getNonceValue()    // nonce
			. ':' . $assinaturaHmac;                // HMAC Hash
		
		/**
		 * Acrescentar parâmetro HMAC na URI original
		 */
		$uri = $request->getUriString()
				. (strpos($request->getUriString(),'?')===false?'?':'&')
				. HMACUriAdapter::URI_PARAM_NAME . '=' . urlencode($authParam);
		
		$request->setUri( $uri );
		
	}

	/**
	 * Assinar requisição (com sessão)
	 * @param Request $request
	 * @throws RuntimeException
	 */
	protected function _signSession( Request $request ) {
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
		$assinaturaHmac = $this->hmac->getHmac( $assinarDados, HMACSession::SESSION_MESSAGE );
	
		/**
		 * Header de autenticação (protocolo versão 1)
		*/
		$headerAuth = HMACHeaderAdapter::VERSION    // versão do protocolo
			. ':' . $assinaturaHmac;                // HMAC Hash
	
		$request->getHeaders()->addHeaderLine(HMACHeaderAdapter::HEADER_NAME, $headerAuth);
	
	}
	
	/**
	 * Verificar assinatura da resposta do servidor (sem sessão)
	 * @param Response $response
	 * @throws RuntimeException
	 */
	protected function _verify( Response $response ) {
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
		$this->hmac->validate( $response->getBody(), $assinatura, HMACSession::SESSION_MESSAGE );
		
	}
	
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
			throw new RuntimeException('HMAC é necessário para a requisição');
		
		if( $request === null )
			$request = $this->getRequest();

		/**
		 * Verificar se é com ou sem sessão
		 */
		if( $this->hmac instanceof HMACSession ) {
			
			/**
			 * Iniciar sessão
			 */
			if( !$this->hmacSession )
				$this->_startSession( $request );
			
			/**
			 * Assinar requisição
			 */
			$this->_signSession($request);
				
			/**
			 * Enviar requisição
			*/
			$response = parent::send($request);
				
			/**
			 * Verificar assinatura da resposta
			*/
			$this->_verify($response);
			$this->hmac->nextMessage(); // Incrementar contagem na sessão após validar resposta
			
		} else {
			/**
			 * Assinar requisição
			 */
			switch ($this->hmacMode) {
				case self::HMAC_URI:
					$this->_signUri($request);
					break;
				case self::HMAC_HEADER:
				default:
					$this->_sign($request);
			}
			
			
			/**
			 * Enviar requisição
			*/
			$response = parent::send($request);
			
			/**
			 * Verificar assinatura da resposta
			*/
			$this->_verify($response);
			
		}
		
		/**
		 * Incrementar contador interno após validar resposta
		 */
		$this->hmacContador++;
		
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
	
	/**
	 * 
	 * @param int $modo
	 * @return \RB\Sphinx\Hmac\Zend\Client\HMACHttpClient
	 */
	public function setHmacMode($modo) {
		$this->hmacMode = $modo;
		return $this;
	}
	
	/**
	 * 
	 * @return int
	 */
	public function getHmacMode() {
		return $this->hmacMode;
	}
	
}