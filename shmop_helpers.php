<?php

/**
 * @param string $str
 * @return string
 */
function str_to_nts(string $str): string
{
	return sprintf("%s\0", $str);
}

/**
 * @param string $str
 * @return string
 */
function str_from_mem(string $str): string
{
	$i = strpos($str, "\0");
	if ($i === false) {
		return $str;
	}
	return substr($str, 0, $i);
}
