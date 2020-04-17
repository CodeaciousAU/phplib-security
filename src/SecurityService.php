<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Acl\Acl;
use Codeacious\Acl\Principal\Principal;

/**
 * Holds the application ACl and the current authentication state.
 */
class SecurityService
{
    /**             
     * @var Acl
     */
    protected $acl;
    
    /**
     * @var User
     */
    protected $currentUser;
    
    /**
     * @var User
     */
    protected $overridingAuditUser;
    
    /**
     * @var Principal
     */
    protected $currentPrincipal;
    
    
    /**
     * @return Acl
     */
    public function getAcl()
    {
        if (!$this->acl)
            $this->acl = new Acl();
        return $this->acl;
    }

    /**
     * @param Acl $acl
     * @return $this
     */
    public function setAcl($acl)
    {
        $this->acl = $acl;
        return $this;
    }
    
    /**
     * @return User|null
     */
    public function getCurrentUser()
    {
        return $this->currentUser;
    }

    /**
     * @param User $value
     * @return $this
     */
    public function setCurrentUser(User $value)
    {
        if ($this->currentUser !== $value)
            $this->resetCurrentPrincipal();
        
        $this->currentUser = $value;
        return $this;
    }
    
    /**
     * @return boolean
     */
    public function hasCurrentUser()
    {
        return ($this->getCurrentUser() !== null);
    }
    
    /**
     * @return $this
     */
    public function clearCurrentUser()
    {
        if ($this->currentUser !== null)
            $this->resetCurrentPrincipal();
        
        $this->currentUser = null;
        return $this;
    }
    
    /**
     * @return User|null
     */
    public function getOverridingAuditUser()
    {
        return $this->overridingAuditUser;
    }

    /**
     * @param User $value
     * @return $this
     */
    public function setOverridingAuditUser(User $value)
    {
        $this->overridingAuditUser = $value;
        return $this;
    }
    
    /**
     * @return boolean
     */
    public function hasOverridingAuditUser()
    {
        return ($this->getOverridingAuditUser() !== null);
    }
    
    /**
     * @return $this
     */
    public function clearOverridingAuditUser()
    {
        $this->overridingAuditUser = null;
        return $this;
    }
    
    /**
     * @return User|null
     */
    public function getCurrentAuditUser()
    {
        if ($this->getOverridingAuditUser())
            return $this->getOverridingAuditUser();
        return $this->getCurrentUser();
    }
    
    /**
     * @return integer Returns 0 if there is no audit user
     */
    public function getCurrentAuditUserId()
    {
        if (($user = $this->getCurrentAuditUser()))
            return $user->getId();
        return 0;
    }
    
    /**
     * Retrieve the security principal which determines access for the current user.
     * 
     * @return Principal
     */
    public function getCurrentPrincipal()
    {
        if (!$this->currentPrincipal)
        {
            if (($user = $this->getCurrentUser()))
                $this->currentPrincipal = $user->getAclPrincipal($this->getAcl());
            else
            {
                $this->currentPrincipal = new Principal('anonymous_user');
                $this->currentPrincipal->grantRole($this->getAcl()->getRole('Guest'))
                                       ->addToAcl($this->getAcl());
            }
        }
        return $this->currentPrincipal;
    }
    
    /**
     * Clear the cached principal, so that the current principal will be re-determined on the next
     * call to getCurrentPrincipal()
     * 
     * @return void
     */
    protected function resetCurrentPrincipal()
    {
        if ($this->currentPrincipal && $this->currentPrincipal instanceof Principal)
            $this->currentPrincipal->removeFromAcl();
        $this->currentPrincipal = null;
    }
}
