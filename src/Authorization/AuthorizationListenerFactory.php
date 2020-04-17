<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authorization;

use Codeacious\Security\SecurityService;
use Codeacious\Stdlib\ArrayTool;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class AuthorizationListenerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');
        $rulesConfig = ArrayTool::getArrayAtPath($config, 'authorization:rules');
        $adapterConfig = ArrayTool::getArrayAtPath($config, 'authorization:adapters');

        $adapterPluginManager = new AdapterPluginManager($container, $adapterConfig);

        /* @var $securityService SecurityService */
        $securityService = $container->get(SecurityService::class);

        return new AuthorizationListener($rulesConfig, $adapterPluginManager, $securityService);
    }
}