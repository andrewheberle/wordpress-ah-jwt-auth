<?php
declare(strict_types=1);

namespace ItalyStrap\Storage;

/**
 * @psalm-api
 */
class Mod implements StoreInterface, ClearableInterface
{
    use MultipleTrait, SetMultipleStoreTrait;

    /**
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        return \get_theme_mod($key, $default);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    public function set(string $key, $value): bool
    {
        return \set_theme_mod($key, $value);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    public function update(string $key, $value): bool
    {
        return \set_theme_mod($key, $value);
    }

    /**
     * @param string $key
     * @return bool
     */
    public function delete(string $key): bool
    {
        \remove_theme_mod($key);
        return true;
    }

    /**
     * @return bool
     */
    public function clear(): bool
    {
        \remove_theme_mods();
        return true;
    }
}
