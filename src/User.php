<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security;

use Codeacious\Acl\Acl;
use Codeacious\Acl\Principal\Principal;

interface User
{
    /**
     * @return mixed
     */
    public function getId();

    /**
     * @return string
     */
    public function getDisplayName();

    /**
     * @return string|null
     */
    public function getFirstName();

    /**
     * @return string|null
     */
    public function getSurname();

    /**
     * @return string|null
     */
    public function getEmailAddress();

    /**
     * @param Acl $acl
     * @return Principal
     */
    public function getAclPrincipal(Acl $acl);
}