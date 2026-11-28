import assert from 'node:assert/strict';
import test from 'node:test';
import { listQueryString, pageQueryString, rangeLabel, readQuery } from '../../resources/js/admin-directory/query.ts';

test('an empty address opens the first page of everyone with nobody selected', () => {
  assert.deepEqual(readQuery(''), { search: '', status: '', group: null, page: 1, subject: null });
});

test('a relying application deep link opens one person', () => {
  assert.equal(readQuery('?subject=subject%2Fwith%2Bchars').subject, 'subject/with+chars');
  assert.equal(pageQueryString(readQuery('?subject=abc')), '?subject=abc');
});

test('malformed values fall back instead of reaching the API', () => {
  const query = readQuery('?status=owner&group=-3&page=0&subject=' + 'x'.repeat(65));
  assert.deepEqual(query, { search: '', status: '', group: null, page: 1, subject: null });
  assert.equal(readQuery('?page=1e3').page, 1);
  assert.equal(readQuery('?q=' + 'a'.repeat(300)).search.length, 255);
});

test('the address keeps only what differs from the default and round-trips', () => {
  const query = { search: ' synthetic ', status: 'disabled', group: 4, page: 3, subject: 's1' };
  const text = pageQueryString(query);
  assert.equal(text, '?q=synthetic&status=disabled&group=4&page=3&subject=s1');
  assert.deepEqual(readQuery(text), { ...query, search: 'synthetic' });
  assert.equal(pageQueryString({ search: '', status: '', group: null, page: 1, subject: null }), '');
});

test('the list request carries filters and paging but never the open person', () => {
  const text = listQueryString({ search: 'syn', status: 'active', group: null, page: 2, subject: 's1' }, 50);
  assert.equal(text, '?search=syn&status=active&page=2&per_page=50');
});

test('the range label counts what the page shows', () => {
  assert.equal(rangeLabel({ page: 1, per_page: 50, total: 1234, last_page: 25 }, 50), '1–50 of 1,234 people');
  assert.equal(rangeLabel({ page: 25, per_page: 50, total: 1234, last_page: 25 }, 34), '1,201–1,234 of 1,234 people');
  assert.equal(rangeLabel({ page: 1, per_page: 50, total: 1, last_page: 1 }, 1), '1–1 of 1 person');
  assert.equal(rangeLabel({ page: 1, per_page: 50, total: 0, last_page: 1 }, 0), 'No people match');
});
