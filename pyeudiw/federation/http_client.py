import aiohttp
import asyncio
import requests


async def fetch(session: dict, url: str, httpc_params: dict) -> str:
    """
    Fetches the content of a URL.

    :param session: a dict representing the current session
    :type session: dict
    :param url: the url where fetch the content
    :type url: str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :returns: the response in string format
    :rtype: str
    """

    async with session.get(url, **httpc_params.get("connection", {})) as response:
        if response.status != 200:  # pragma: no cover
            # response.raise_for_status()
            return ""
        return await response.text()


async def fetch_all(session: dict, urls: list[str], httpc_params: dict) -> list[str]:
    """
    Fetches the content of a list of URL.

    :param session: a dict representing the current session
    :type session: dict
    :param urls: the url list where fetch the content
    :type urls: list[str]
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :returns: the list of responses in string format
    :rtype: list[str]
    """

    tasks = []
    for url in urls:
        task = asyncio.create_task(fetch(session, url, httpc_params))
        tasks.append(task)
    results = await asyncio.gather(*tasks)
    return results


async def http_get(urls, httpc_params: dict, sync=True):
    """
    Perform a GET http call.

    :param session: a dict representing the current session
    :type session: dict
    :param urls: the url list where fetch the content
    :type urls: list[str]
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :returns: the list of responses in string format
    :rtype: list[str]
    """
    if sync:
        _conf = {
            'verify': httpc_params['connection']['ssl'],
            'timeout': httpc_params['session']['timeout']
        }
        res = [
            requests.get(url, **_conf).content  # nosec - B113
            for url in urls
        ]
        return res

    if not isinstance(httpc_params['session']['timeout'], aiohttp.ClientTimeout):
        httpc_params['session']['timeout'] = aiohttp.ClientTimeout(
            total=httpc_params['session']['timeout']
        )

    async with aiohttp.ClientSession(**httpc_params.get("session", {})) as session:
        text = await fetch_all(session, urls, httpc_params)
        return text


if __name__ == "__main__":  # pragma: no cover
    httpc_params = {
        "connection": {"ssl": True},
        "session": {"timeout": aiohttp.ClientTimeout(total=4)},
    }
    urls = [
        "http://127.0.0.1:8001/.well-known/openid-federation",
        "http://127.0.0.1:8000/.well-known/openid-federation",
        "http://asdasd.it",
        "http://127.0.0.1:8001/.well-known/openid-federation",
        "http://google.it",
    ]
    asyncio.run(http_get(urls, httpc_params=httpc_params))
