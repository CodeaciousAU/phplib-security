<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Controller\Plugin;

use Codeacious\Acl\Principal\Principal;
use Codeacious\Security\SecurityService;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class CurrentPrincipal extends AbstractPlugin
{
    /**
     * @var SecurityService
     */
    private $securityService;

    /**
     * @param SecurityService $securityService
     */
    public function __construct(SecurityService $securityService)
    {
        $this->securityService = $securityService;
    }

    /**
     * @return Principal
     */
    public function __invoke()
    {
        return $this->securityService->getCurrentPrincipal();
    }
}