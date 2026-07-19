async function settleWithConcurrency(items, concurrency, worker) {
  const results = new Array(items.length);
  const safeConcurrency = Number.isFinite(concurrency) && concurrency > 0 ? concurrency : 1;
  const workerCount = Math.max(1, Math.min(safeConcurrency, items.length));
  let nextIndex = 0;

  async function runNext() {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex++;
      try {
        results[currentIndex] = { status: 'fulfilled', value: await worker(items[currentIndex]) };
      } catch (reason) {
        results[currentIndex] = { status: 'rejected', reason };
      }
    }
  }

  const workers = Array.from(
    { length: workerCount },
    () => runNext()
  );
  await Promise.all(workers);
  return results;
}

module.exports = { settleWithConcurrency };
