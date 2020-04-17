<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Mvc\CsrfPreventionService;
use Codeacious\Security\SecurityService;
use Codeacious\Security\User;

/**
 * Provides functionality for setting or clearing the current web session user, and persisting it
 * across requests.
 */
abstract class PersistenceMethod
{
    /**
     * @var SecurityService
     */
    protected $securityService;

    /**
     * @var CsrfPreventionService
     */
    protected $csrfPreventionService;


    /**
     * @param SecurityService $securityService
     * @return $this
     */
    public function setSecurityService($securityService)
    {
        $this->securityService = $securityService;
        return $this;
    }

    /**
     * @param CsrfPreventionService $csrfPreventionService
     * @return $this
     */
    public function setCsrfPreventionService($csrfPreventionService)
    {
        $this->csrfPreventionService = $csrfPreventionService;
        return $this;
    }

    /**
     * Set the logged-in user for the current session.
     *
     * @param User|null $user Pass null to clear the session user
     * @param User|null $realUser If not null, this starts a session whereby $realUser is
     *    impersonating $user. Not applicable if $user is null.
     * @return void
     */
    public function setSessionUser(User $user=null, User $realUser=null)
    {
        if ($user)
        {
            //Set the user for the remainder of this request
            $this->securityService->setCurrentUser($user);

            //If impersonation is in effect, make sure actions will be logged as the real user.
            if ($realUser)
                $this->securityService->setOverridingAuditUser($realUser);

            //Set the user for future requests
            $this->persistState($user, $realUser);
        }
        else
        {
            //Clear the user for the remainder of this request
            $this->securityService->clearCurrentUser();

            //Clear the user for future requests
            $this->clearState();
        }

        //Generate a new CSRF token for good measure. This will ensure that any forms the user may
        //have open will expire and won't apply changes unexpectedly to the newly logged-in account.
        $this->csrfPreventionService->resetToken();
    }

    /**
     * @param User $user
     * @param User|null $realUser
     * @return void
     */
    protected abstract function persistState(User $user, User $realUser=null);

    /**
     * @return void
     */
    protected abstract function clearState();
}