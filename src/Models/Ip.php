<?php

namespace Edoardoagnelli1357\LaravelWaf;

use Illuminate\Database\Eloquent\Model;

class Ip extends Model {
    protected $table= 'waf_ips';

    protected $fillable = [];
}
