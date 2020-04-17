<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\ServiceManager\AbstractPluginManager;

class AdapterPluginManager extends AbstractPluginManager
{
    protected $instanceOf = AdapterInterface::class;
}