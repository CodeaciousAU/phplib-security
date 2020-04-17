<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Mvc\CsrfPreventionService;
use Codeacious\Security\Exception\ConfigurationException;
use Codeacious\Security\SecurityService;
use Codeacious\Security\Session\TokenProvider\TokenProviderInterface;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class CookieServiceFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');

        $cookieConfig = (isset($config['security']['session']['cookie']))
            ? $config['security']['session']['cookie'] : [];

        if (!isset($config['security']['session']['token_provider']))
        {
            throw new ConfigurationException('Missing config key security.session.token_provider');
        }
        $tokenProvider = $container->get($config['security']['session']['token_provider']);
        if (! $tokenProvider instanceof TokenProviderInterface)
        {
            throw new ConfigurationException('The configured token provider service "'
                .$config['security']['session']['token_provider'].'" did not return an object '
                .'that implements '.TokenProviderInterface::class);
        }

        /* @var $securityService SecurityService */
        $securityService = $container->get(SecurityService::class);

        /* @var $csrfPreventionService CsrfPreventionService */
        $csrfPreventionService = $container->get(CsrfPreventionService::class);

        $service = new CookieService($cookieConfig);
        $service
            ->setTokenProvider($tokenProvider)
            ->setSecurityService($securityService)
            ->setCsrfPreventionService($csrfPreventionService);

        return $service;
    }
}