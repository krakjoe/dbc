<?php
class Foo {

	<<pre($arg < 10)>>
	public function thing($arg) {
		return $arg;
	}
}

$foo = new Foo();
var_dump($foo->thing(20));
?>
