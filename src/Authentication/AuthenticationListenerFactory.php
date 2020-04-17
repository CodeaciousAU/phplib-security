<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\Exception\ConfigurationException;
use Codeacious\Security\SecurityService;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class AuthenticationListenerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');
        $rulesConfig = isset($config['authentication']['rules'])
            ? $config['authentication']['rules'] : [];
        $adapterConfig = isset($config['authentication']['adapters'])
            ? $config['authentication']['adapters'] : [];

        $adapterPluginManager = new AdapterPluginManager($container, $adapterConfig);

        if (!isset($config['authentication']['user_lookup_strategy']))
        {
            throw new ConfigurationException('Missing config key '
                .'authentication.user_lookup_strategy');
        }
        $userLookupStrategy = $container->get($config['authentication']['user_lookup_strategy']);
        if (! $userLookupStrategy instanceof UserLookupStrategy)
        {
            throw new ConfigurationException('The configured user lookup strategy service "'
                .$config['authentication']['user_lookup_strategy'].'" did not return an object '
                .'that implements '.UserLookupStrategy::class);
        }

        /* @var $securityService SecurityService */
        $securityService = $container->get(SecurityService::class);

        $service = new AuthenticationListener();
        $service
            ->setRulesConfig($rulesConfig)
            ->setAdapterPluginManager($adapterPluginManager)
            ->setUserLookupStrategy($userLookupStrategy)
            ->setSecurityService($securityService);

        return $service;
    }
}