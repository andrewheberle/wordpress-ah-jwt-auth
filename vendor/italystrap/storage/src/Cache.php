<?php
declare(strict_types=1);

namespace ItalyStrap\Storage;

/**
 * @see \wp_cache_add()
 * @see \wp_cache_get()
 * @see \wp_cache_set()
 * @see \wp_cache_replace()
 * @see \wp_cache_delete()
 * @see \wp_cache_flush()
 *
 * @psalm-api
 */
class Cache implements CacheInterface, ClearableInterface, IncrDecrInterface
{
    use NormalizeTtlTrait;

    private string $group;

    public function __construct(string $group = 'default')
    {
        $this->group = $group;
    }

    public function set(string $key, $value, ?int $ttl = null): bool
    {
        $ttl = $this->parseTtl($ttl);
        return \wp_cache_set($key, $value, $this->group, $ttl);
    }

    public function get(string $key, $default = null)
    {
        /**
         * @var mixed $value
         */
        $value = \wp_cache_get($key, $this->group);
        if ($value === 0) {
            return $value;
        }

        return $value ?: $default;
    }

    public function update(string $key, $value, ?int $ttl = null): bool
    {
        return $this->set($key, $value, $ttl);
    }

    public function delete(string $key): bool
    {
        if (empty($key)) {
            return false;
        }

        if (!$this->get($key)) {
            return true;
        }

        return \wp_cache_delete($key, $this->group);
    }

    /**
     * @param string $key
     * @param int $offset
     * @return false|int
     * @psalm-suppress MixedInferredReturnType
     */
    public function increment(string $key, int $offset = 1)
    {
        /** @psalm-suppress MixedReturnStatement */
        return \wp_cache_incr($key, $offset, $this->group);
    }

    /**
     * @param string $key
     * @param int $offset
     * @return false|int
     * @psalm-suppress MixedInferredReturnType
     */
    public function decrement(string $key, int $offset = 1)
    {
        /** @psalm-suppress MixedReturnStatement */
        return \wp_cache_decr($key, $offset, $this->group);
    }

    public function clear(): bool
    {
        return \wp_cache_flush();
    }

    public function setMultiple(iterable $values, ?int $ttl = null): bool
    {
        $newValues = $this->iteratorToArray($values);
        $ttl = $this->parseTtl($ttl);
        foreach (\wp_cache_set_multiple($newValues, $this->group, $ttl) as $value) {
            if (!$value) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param iterable $keys
     * @param mixed $default
     * @return iterable<mixed, mixed|null>
     */
    public function getMultiple(iterable $keys, $default = null): iterable
    {
        $newValues = $this->iteratorToArray($keys);
        /**
         * @var mixed $value
         */
        foreach (\wp_cache_get_multiple($newValues, $this->group) as $key => $value) {
            yield $key => $value ?: $default;
        }
    }

    public function deleteMultiple(iterable $keys): bool
    {
        /** @var string $key */
        foreach ($keys as $key) {
            if (!$this->delete($key)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param iterable $values
     * @return array
     */
    private function iteratorToArray(iterable $values): array
    {
        return $values instanceof \Traversable ? \iterator_to_array($values) : $values;
    }
}
