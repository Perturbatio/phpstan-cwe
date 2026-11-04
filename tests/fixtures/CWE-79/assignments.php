<?php

$name = $_GET['name'];
$alias = $name;
$html = '<p>' . $alias . '</p>';
echo $html; // Report: Input passes through two assignments and concatenation.
$html .= ' tail';
print $html; // Report: Concatenation keeps the input.
$html = 'prefix';
$html .= $_POST['comment'];
echo $html; // Report: Concatenation adds request input.
$html = "Hello {$alias}";
echo $html; // Report: Interpolation keeps the input.
$html = strtoupper(trim($alias));
echo $html; // Report: Text calls do not escape HTML.
$html = htmlspecialchars($alias);
echo $html; // No report: The assigned value is escaped.
$html .= $alias;
echo $html; // Report: Unescaped input is added after escaping.
$html = htmlentities($html);
echo $html; // No report: The whole value is escaped.
$html = (int) $alias;
echo $html; // No report: An integer cannot add HTML.
$html = (float) $alias;
echo $html; // No report: A float cannot add HTML.
$html = $alias;
$html = 'fixed';
echo $html; // No report: A fixed value replaces the input.
echo $alias; // Report: Replacing a copy does not change the original.
$name = 'fixed';
echo $alias; // Report: The copy keeps the earlier input.
echo $name; // No report: The source variable was replaced.
echo htmlspecialchars($alias), htmlentities($alias); // No report: Both values are escaped.
echo 'fixed', $alias, $alias; // Report: Report one echo only once.

function firstOutput(): void
{
    $local = $_COOKIE['value'];
    echo $local; // Report: Local request input reaches HTML.
}

function secondOutput(string $local): void
{
    echo $local; // No report: Another function has a separate scope.
}

class FirstOutput
{
    public function render(): void
    {
        $local = $_REQUEST['value'];
        echo $local; // Report: Method input reaches HTML.
    }
}

class SecondOutput
{
    public function render(string $local): void
    {
        echo $local; // No report: Another class has a separate scope.
    }
}

$callback = function (): void {
    echo $_GET['name']; // Report: Direct closure output is still checked.
    $name = $_POST['name']; // No report: Closure assignments are not tracked.
};
echo $name; // No report: A closure assignment does not change the outer value.
echo $missing; // No report: There is no known request source.
$html = escapeshellarg($alias);
echo $html; // Report: Shell escaping does not protect HTML.
$html = htmlspecialchars($alias, ENT_NOQUOTES);
echo $html; // Report: Non-default escape calls are not accepted.
