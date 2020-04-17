<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\View\Helper;

use Codeacious\Security\SecurityService;
use Laminas\View\Helper\AbstractHelper;

/**
 * View helper to get the User object representing the currently logged in user.
 * Returns null if there is no user logged in.
 */
class CurrentUser extends AbstractHelper
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
     * @return \Codeacious\Security\User|null
     */
    public function __invoke()
    {
        return $this->securityService->getCurrentUser();
    }
}