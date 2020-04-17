<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authorization;

use Codeacious\Security\Authorization\Adapter\AdapterInterface;
use Codeacious\Security\SecurityService;
use Laminas\EventManager\AbstractListenerAggregate;
use Laminas\EventManager\EventManagerInterface;
use Laminas\Http\PhpEnvironment\Request as HttpRequest;
use Laminas\Http\Response as HttpResponse;
use Laminas\Mvc\MvcEvent;

/**
 * Chooses the appropriate authorization adapter for the request, and queries it to see if the
 * request should be allowed.
 */
class AuthorizationListener extends AbstractListenerAggregate
{
    /**
     * @var array
     */
    private $rulesConfig = [];

    /**
     * @var AdapterPluginManager
     */
    private $adapterPluginManager;

    /**
     * @var SecurityService
     */
    private $securityService;


    public function __construct(array $rulesConfig, AdapterPluginManager $adapterPluginManager,
                                SecurityService $securityService)
    {
        $this->rulesConfig = $rulesConfig;
        $this->adapterPluginManager = $adapterPluginManager;
        $this->securityService = $securityService;
    }

    /**
     * {@inheritdoc}
     */
    public function attach(EventManagerInterface $events, $priority=1)
    {
        /**
         * Request-handling event sequence is bootstrap, route, dispatch, render, finish.
         */
        $this->listeners[] = $events->attach(
            MvcEvent::EVENT_DISPATCH, array($this, 'preDispatch'), 90
        );
    }

    /**
     * @param MvcEvent $e
     * @return mixed
     */
    public function preDispatch(MvcEvent $e)
    {
        /* @var $request HttpRequest */
        $request = $e->getRequest();

        //Skip authentication for console requests or OPTIONS requests
        if (! ($request instanceof HttpRequest) || $request->isOptions())
            return null;

        $route = $e->getRouteMatch();
        $routeName = $route->getMatchedRouteName();
        $controllerName = $route->getParam('controller');
        $relPath = $this->getRelativePath($request);

        //Apply the first authentication rule that matches this request
        if (($rule = $this->getMatchingRule($relPath, $routeName, $controllerName)))
        {
            $authResult = null;
            if (!empty($rule['adapter']))
            {
                /* @var $adapter AdapterInterface */
                $adapter = $this->adapterPluginManager->get($rule['adapter']);
                $authResult = $adapter->isAuthorized($this->securityService->getCurrentPrincipal(),
                    $e);
            }

            if ($authResult === false)
            {
                if (!empty($rule['forward_if_unauthorized']))
                {
                    $route->setMatchedRouteName(null);
                    $route->setParam('controller', $rule['forward_if_unauthorized']['controller']);
                    $route->setParam('action', $rule['forward_if_unauthorized']['action']);
                    return null;
                }
                else
                {
                    $response = $e->getResponse(); /* @var $response HttpResponse */
                    $response->setStatusCode(403);
                    $response->setContent('Access denied');
                    return $response;
                }
            }
        }

        return null;
    }

    /**
     * @param string $urlPath The requested URL path, relative to the base URL
     * @param string|null $routeName The name of the matched route, if there was one
     * @param string|null $controllerName The name of the controller that the matched route
     *    specified, if there was one
     * @return array|null Array of parameters for the matched rule, null if no rule matched
     */
    protected function getMatchingRule($urlPath, $routeName=null, $controllerName=null)
    {
        //Find the first authorization rule that matches this request
        foreach ($this->rulesConfig as $rule)
        {
            //Test each rule criterion. If there are multiple criteria, all must match.
            $isMatch = true;
            if (isset($rule['url_pattern']))
            {
                $regex = '/'.str_replace('/', '\/', $rule['url_pattern']).'/';
                if (!preg_match($regex, $urlPath))
                    $isMatch = false;
            }
            if (isset($rule['route_name']))
            {
                if (!is_array($rule['route_name']))
                    $rule['route_name'] = array($rule['route_name']);
                if ($routeName == null || !in_array($routeName, $rule['route_name']))
                    $isMatch = false;
            }
            if (isset($rule['controller']))
            {
                if (!is_array($rule['controller']))
                    $rule['controller'] = array($rule['controller']);
                if ($controllerName === null || !in_array($controllerName, $rule['controller']))
                    $isMatch = false;
            }

            //If this rule is a match, return its associated auth config
            if ($isMatch)
                return $rule;
        }

        return null;
    }

    /**
     * Get the URI path of the request, relative to the application base URL.
     *
     * @param HttpRequest $request
     * @return string
     */
    protected function getRelativePath(HttpRequest $request)
    {
        $basePath = $request->getBasePath();
        $relPath = $request->getUri()->getPath();
        if (!empty($basePath) && strpos($relPath, $basePath) === 0)
            $relPath = substr($relPath, strlen($basePath));
        return $relPath;
    }
}