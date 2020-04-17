<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authorization\Adapter;

use Codeacious\Acl\Acl;
use Codeacious\Acl\Principal\Principal;
use Laminas\Mvc\MvcEvent;

class ControllerAclAdapter implements AdapterInterface
{
    function isAuthorized(Principal $principal, MvcEvent $event): bool
    {
        $route = $event->getRouteMatch();
        if (!$route)
            return true;

        $controllerName = $route->getParam('controller');
        if (empty($controllerName))
            return true;

        return $principal->hasPermission(Acl::PERMISSION_QUERY, $controllerName);
    }
}