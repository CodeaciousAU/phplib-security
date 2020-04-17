<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Controller\Plugin;

use Codeacious\Security\SecurityService;
use Laminas\Mvc\Controller\Plugin\AbstractPlugin;

class IsLoggedIn extends AbstractPlugin
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
     * @return bool
     */
    public function __invoke()
    {
        return $this->securityService->hasCurrentUser();
    }
}