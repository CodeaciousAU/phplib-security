<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authorization;

use Codeacious\Security\Authorization\Adapter\AdapterInterface;
use Laminas\ServiceManager\AbstractPluginManager;

class AdapterPluginManager extends AbstractPluginManager
{
    protected $instanceOf = AdapterInterface::class;
}