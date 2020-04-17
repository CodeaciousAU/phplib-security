<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\View\Helper;

use Codeacious\Security\SecurityService;
use Laminas\View\Helper\AbstractHelper;

/**
 * View helper to check if a user is impersonating another user for the current web session.
 */
class IsImpersonationActive extends AbstractHelper
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
        $overrideUser = $this->securityService->getOverridingAuditUser();
        return ($user != null && $overrideUser != null && $user != $overrideUser);
    }
}