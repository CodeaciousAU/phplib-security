<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session\TokenProvider;

use Codeacious\Security\WebTokenManager;
use Interop\Container\ContainerInterface;
use Laminas\Http\Request as HttpRequest;
use Laminas\ServiceManager\Factory\FactoryInterface;

class JwtProviderFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        /* @var $tokenManager WebTokenManager */
        $tokenManager = $container->get(WebTokenManager::class);

        $provider = new JwtProvider();
        $provider->setTokenManager($tokenManager);

        $request = $container->get('Request');
        if ($request instanceof HttpRequest)
            $provider->setTokenAudience('https://'.$request->getUri()->getHost());

        return $provider;
    }
}