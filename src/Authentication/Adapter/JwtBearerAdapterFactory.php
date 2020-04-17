<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Codeacious\Security\Authentication\JwtSignerFactory;
use Codeacious\Security\Exception\ConfigurationException;
use Codeacious\Security\Exception\RuntimeException;
use Codeacious\Stdlib\ArrayTool;
use Interop\Container\ContainerInterface;
use Laminas\Http;
use Laminas\ServiceManager\Factory\FactoryInterface;
use Lcobucci\JWT\Signer;

class JwtBearerAdapterFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $request = $container->get('Request');
        if (!$request instanceof Http\Request)
            throw new RuntimeException('JwtBearerAdapter is only compatible with HTTP requests');

        $config = ArrayTool::getArrayAtPath($container->get('config'), 'authentication:jwt_bearer');
        if (empty($config['algorithm']))
            throw new ConfigurationException('Missing required config key "algorithm"');

        $signer = JwtSignerFactory::signerForAlgorithm($config['algorithm']);
        $keyKey = ($signer instanceof Signer\Rsa || $signer instanceof Signer\Ecdsa)
            ? 'public_key' : 'key';

        if (empty($config[$keyKey]))
            throw new ConfigurationException('Missing required config key "'.$keyKey.'"');
        if (($key = file_get_contents($config[$keyKey])) === false)
            throw new RuntimeException('Unable to read key file '.$config[$keyKey]);
        $verificationKey = new Signer\Key($key);

        $issuer = ArrayTool::getValueAtPath($config, 'issuer');

        return new JwtBearerAdapter($request, $signer, $verificationKey, $issuer);
    }
}