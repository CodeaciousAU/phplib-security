<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Acl\Acl;
use Codeacious\Security\Exception\ConfigurationException;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

/**
 * Factory to create instances of SecurityService.
 */
class SecurityServiceFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $service = new SecurityService();

        //Use a custom ACL if configured
        $config = $container->get('config');
        if (isset($config['security']['acl']))
        {
            $acl = $container->get($config['security']['acl']);
            if (! $acl instanceof Acl)
            {
                throw new ConfigurationException('The configured ACL service must be an object of '
                    .'class '.Acl::class);
            }
            $service->setAcl($acl);
        }

        return $service;
    }
}
