<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Security\Exception\ConfigurationException;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class WebTokenManagerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');
        if (!isset($config['security']['web_token_manager']))
        {
            throw new ConfigurationException('Missing configuration key '
                .'security.web_token_manager');
        }

        return new WebTokenManager($config['security']['web_token_manager']);
    }
}