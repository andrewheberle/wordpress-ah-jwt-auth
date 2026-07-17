<?php
declare(strict_types=1);

namespace ItalyStrap\Storage;

/**
 * @see \get_option()
 * @see \add_option()
 * @see \update_option()
 * @see \delete_option()
 * @psalm-api
 */
class Option implements StoreInterface
{
    use MultipleTrait, SetMultipleStoreTrait;

    /**
     * @param string $key
     * @param mixed $default
     * @return false|mixed|null
     */
    public function get(string $key, $default = null)
    {
        return \get_option($key, $default);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    public function set(string $key, $value): bool
    {
        return \add_option($key, $value);
    }

    /**
     * @param string $key
     * @param mixed $value
     * @return bool
     */
    public function update(string $key, $value): bool
    {
        return \update_option($key, $value);
    }

    /**
     * @param string $key
     * @return bool
     */
    public function delete(string $key): bool
    {
        if (empty($key)) {
            return false;
        }

        if (!$this->get($key)) {
            return true;
        }

        return \delete_option($key);
    }
}
