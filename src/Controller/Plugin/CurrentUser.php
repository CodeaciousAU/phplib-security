<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Controller\Plugin;

use Codeacious\Security\SecurityService;
use Codeacious\Security\User;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class CurrentUser extends AbstractPlugin
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
     * @return User|null
     */
    public function __invoke()
    {
        return $this->securityService->getCurrentUser();
    }
}