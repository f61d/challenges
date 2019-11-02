<?php
/**
 * Created by lingFeng.
 */

function check($file)
    {
        $whitelist = array('showimage.php');
        if (! isset($file) || !is_string($file)) {
            return false;
        }

        if (in_array($file, $whitelist)) {
            return true;
        }

        $file = mb_substr($file,0,mb_strpos($file . '?', '?'));
        if (in_array($file, $whitelist)) {
            return true;
        }

        $file = urldecode($file);
        $file = mb_substr($file,0, mb_strpos($file . '?', '?'));
        if (in_array($file, $whitelist)) {
            return true;
        }

        return false;
    }
