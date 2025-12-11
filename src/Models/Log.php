<?php

namespace Edoardoagnelli1357\LaravelWaf;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Log extends Model
{
    use SoftDeletes;

    protected $table = 'waf_logs';

    protected $fillable = [];

    public function ip()
    {
        return $this->belongsTo(Ip::class, 'ip_id', 'id');
    }
}
