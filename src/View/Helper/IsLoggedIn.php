<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\View\Helper;

use Codeacious\Security\SecurityService;
use Laminas\View\Helper\AbstractHelper;

/**
 * View helper to check if there is a user logged in to the application.
 */
class IsLoggedIn extends AbstractHelper
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
        $user = $this->securityService->getCurrentUser();
        return ($user != null);
    }
}