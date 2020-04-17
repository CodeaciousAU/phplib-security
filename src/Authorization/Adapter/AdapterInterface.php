<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authorization\Adapter;

use Codeacious\Acl\Principal\Principal;
use Laminas\Mvc\MvcEvent;

interface AdapterInterface
{
    function isAuthorized(Principal $principal, MvcEvent $event): bool;
}