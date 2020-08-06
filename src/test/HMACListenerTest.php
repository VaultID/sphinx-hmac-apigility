<?php
use PHPUnit\Framework\TestCase;
use RB\Sphinx\Hmac\Zend\Server\HMACListener;

final class HMACListenerTest extends TestCase
{
    protected $config;
    protected $requestProps;
    protected $controller = 'ApplicationManager\\V1\\Rest\\Lock\\Controller';

    protected function setUp()
    {
        $this->config = ['rb_sphinx_hmac_server' => [
            // Opcionalmente, defina seletor e/ou adapter padrão a ser utilizado nos Controller's com HMAC ativo
            'default_selector' => 'HMACSelectorDefault',
            'default_adapter' => 'HMACAdapterDefault',
            
            // Defina quais controller's utilizarão autenticação HMAC
            'controllers' => [
                $this->controller => [
                    'collection' => [ //Pluralidade
                        'POST' => [ //Método
                            'selector' => 'HMAC',
                            'adapter' => 'HMACUriAdapter'
                        ],
                        'GET' => false
                    ],
                    'entity' => [
                        'POST' => [
                            'selector' => 'HMAC',
                            'adapter' => 'HMACUriAdapter'
                        ],
                        'GET' => false
                    ]
                ]
            ]
        ]];
        $this->requestProps = [
            'controller' => $this->controller,
            'plurality' => 'collection',
            'method' => 'POST'
        ];
    }

    public function testGetActionConfigMetodo(): void
    {
        $listener = new HMACListener();

        // Obtendo o HMAC configurado
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMAC', $selector);
        $this->assertEquals('HMACUriAdapter', $adapter);

        // Ignorando o HMAC
        $this->requestProps['method'] = 'GET';
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertFalse($selector);
        $this->assertFalse($adapter);
        
        // Obtendo o HMAC default
        $this->requestProps['method'] = 'PATCH';
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMACSelectorDefault', $selector);
        $this->assertEquals('HMACAdapterDefault', $adapter);
    }

    public function testGetActionConfigPluralidade(): void
    {
        $listener = new HMACListener();
        $this->config['rb_sphinx_hmac_server']['controllers'][$this->controller] = [
            'collection' => [ //Método
                'selector' => 'HMAC',
                'adapter' => 'HMACUriAdapter'
            ],
            'entity' => false
        ];

        // Obtendo o HMAC configurado
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMAC', $selector);
        $this->assertEquals('HMACUriAdapter', $adapter);

        // Ignorando o HMAC
        $this->requestProps['plurality'] = 'entity';
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertFalse($selector);
        $this->assertFalse($adapter);
        
        // Obtendo o HMAC default
        unset($this->config['rb_sphinx_hmac_server']['controllers'][$this->controller]['entity']);
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMACSelectorDefault', $selector);
        $this->assertEquals('HMACAdapterDefault', $adapter);
    }

    public function testGetActionConfigController(): void
    {
        $listener = new HMACListener();
        $this->config['rb_sphinx_hmac_server']['controllers'][$this->controller] = [
            'selector' => 'HMAC',
            'adapter' => 'HMACUriAdapter'
        ];

        // Obtendo o HMAC configurado
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMAC', $selector);
        $this->assertEquals('HMACUriAdapter', $adapter);

        // Ignorando o HMAC
        $this->config['rb_sphinx_hmac_server']['controllers'][$this->controller] = false;
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertFalse($selector);
        $this->assertFalse($adapter);
        
        // Obtendo o HMAC default
        $this->requestProps['controller'] = 'Controller\\Que\\Nao\\Existe';
        $selector = $listener->_getActionConfig('selector', $this->requestProps, $this->config);
        $adapter = $listener->_getActionConfig('adapter', $this->requestProps, $this->config);
        $this->assertEquals('HMACSelectorDefault', $selector);
        $this->assertEquals('HMACAdapterDefault', $adapter);
    }
}