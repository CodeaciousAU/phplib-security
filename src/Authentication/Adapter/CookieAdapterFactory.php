<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Codeacious\Security\Session\CookieService;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class CookieAdapterFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $cookieService = $container->get(CookieService::class);

        $adapter = new CookieAdapter();
        $adapter->setCookieService($cookieService);

        return $adapter;
    }
}