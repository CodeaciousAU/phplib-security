<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Doctrine;

use Codeacious\Security\SecurityService;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

class AuditEventSubscriberFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        /* @var $securityService SecurityService */
        $securityService = $container->get(SecurityService::class);

        $service = new AuditEventSubscriber();
        $service->setSecurityService($securityService);

        return $service;
    }
}