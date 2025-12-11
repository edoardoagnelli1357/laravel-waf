<?php

use Closure;
use Illuminate\Support\Facades\Request;
use Symfony\Component\HttpFoundation\IpUtils;

abstract class Mddleware
{
    public Request|array|string|null $request = null;

    public ?string $middleware = null;

    public ?int $user_id = null;

    public function handle($request, Closure $next)
    {
        if($this->skip($request)){
            return $next($request);
        }


        return $next($request);
    }

    public function skip($request): bool
    {
        $this->prepare($request);
        
        if ($this->isDisabled($this->middleware)) {
            return true;
        }

        if ($this->isWhiteList()) {
            return true;
        }

        if($this->isMethod()){
            return true;
        }

        if($this->isRoute()){
            return true;
        }

        return false;
    }

    public function check($patterns):bool{
        $log = null;

        foreach($pattern as $pattern){
            if(!$match = $this->match($pattern, $this->request->input())){
                continue;
            }
            $log = $this->log();

            break;
        }
        return false;
    }

    public function prepare($request): void
    {
        $this->request = $request;
        $this->middleware = strtolower((new ReflectionClass($this))->getShortName());
        $this->user_id = auth()->id;
    }

    public function match($pattern, $input){
        $result = false;

        if(!is_array($input) && !is_string($input)){
            return false;
        }
        if(!is_array($input)){
            return preg_match($pattern, $input);
        }

        foreach($input as $key => $value){
            if(empty($value)){
                continue;
            }

            if(is_array($value)){
                if(!$result= $this->match($pattern, $input)){
                    continue;
                }

                break;
            }

            if($this->isInput($key)){
                continue;
            }

        }
    }

    public function isInput($name, $middleware = null){
        $middleware = $middleware ??$this->middleware;

        if (! $inputs = config('firewall.middleware.' . $middleware . '.inputs')) {
            return true;
        }

        if (! empty($inputs['only']) && ! in_array((string) $name, (array) $inputs['only'])) {
            return false;
        }

        return ! in_array((string) $name, (array) $inputs['except']);
    }

    public function isEnabled($middleware = null): bool
    {
        $middleware = $middleware ?? $this->middleware;

        return config('waf.middleware.'.$middleware.'.enabled', config('waf.enabled'));
    }

    public function isDisabled($middleware = null): bool
    {
        return ! $this->isEnabled($middleware);
    }

    public function isWhiteList()
    {
        return IpUtils::checkIp($this->ip(), config('waf.whitelist'));
    }

    public function isMethod($middleware = null):bool{
        $middleware = $middleware ?? $this->middleware;

        if (! $methods = config('firewall.middleware.' . $middleware . '.methods')) {
            return false;
        }

        if (in_array('all', $methods)) {
            return true;
        }

        return in_array(strtolower($this->request->method()), $methods);
    }

    public function isRoute($middleware = null)
    {
        $middleware = $middleware ?? $this->middleware;

        if (! $routes = config('firewall.middleware.' . $middleware . '.routes')) {
            return false;
        }

        foreach ($routes['except'] as $ex) {
            if (! $this->request->is($ex)) {
                continue;
            }

            return true;
        }

        foreach ($routes['only'] as $on) {
            if ($this->request->is($on)) {
                continue;
            }

            return true;
        }

        return false;
    }

    public function ip()
    {
        if ($cf_ip = $this->request->header('CF_CONNECTING_IP')) {
            $ip = $cf_ip;
        } else {
            $ip = $this->request->ip();
        }

        return $ip;
    }
}
