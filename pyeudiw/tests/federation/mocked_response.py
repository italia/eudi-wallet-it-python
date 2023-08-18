
from . base import intermediate_ec_signed, intermediate_es_wallet_signed, leaf_wallet_signed, ta_ec_signed, ta_es_signed

import logging

logger = logging.getLogger(__name__)


class DummyContent:
    def __init__(self, content):
        self.content = content.encode()
        self.status_code = 200


class EntityResponse:
    def __init__(self):
        self.status_code = 200
        self.req_counter = 0
        self.result = None


class EntityResponseWithIntermediate(EntityResponse):
    @property
    def content(self):

        resp_seq = {
            0: ta_ec_signed,
            1: leaf_wallet_signed,
            2: intermediate_ec_signed,
            3: intermediate_es_wallet_signed,
            4: ta_es_signed
        }

        self.result = resp_seq.get(self.req_counter, None)
        self.req_counter += 1
        if self.result:
            return self.result
        else:
            raise NotImplementedError(
                "The mocked resposes seems to be not aligned with the correct flow"
            )

# class EntityResponseNoIntermediateSignedJwksUri(EntityResponse):
    # @property
    # def content(self):
        # if self.req_counter == 0:
            # self.result = self.trust_anchor_ec()
        # elif self.req_counter == 1:
            # self.result = self.rp_ec()
        # elif self.req_counter == 2:
            # self.result = self.fetch_rp_from_ta()
        # elif self.req_counter == 3:
            # metadata = copy.deepcopy(
            # rp_conf['metadata']['openid_relying_party'])
            # _jwks = metadata.pop('jwks')
            # fed_jwks = rp_conf['jwks_fed'][0]
            # self.result = create_jws(_jwks, fed_jwks)
            # return self.result.encode()
        # elif self.req_counter > 3:
            # raise NotImplementedError(
            # "The mocked resposes seems to be not aligned with the correct flow"
            # )

        # return self.result_as_jws()


# class EntityResponseWithIntermediate(EntityResponse):
    # @property
    # def content(self):
        # if self.req_counter == 0:
            # self.result = self.trust_anchor_ec()
        # elif self.req_counter == 1:
            # self.result = self.rp_ec()
        # elif self.req_counter == 2:
            # sa = FederationEntityConfiguration.objects.get(
            # sub=intermediary_conf["sub"])
            # self.result = DummyContent(sa.entity_configuration_as_jws)
        # elif self.req_counter == 3:
            # url = reverse("oidcfed_fetch")
            # self.result = self.client.get(
            # url,
            # data={
            # "sub": rp_onboarding_data["sub"],
            # "iss": intermediary_conf["sub"],
            # },
            # )
        # elif self.req_counter == 4:
            # url = reverse("oidcfed_fetch")
            # self.result = self.client.get(
            # url, data={"sub": intermediary_conf["sub"]})
        # elif self.req_counter == 5:
            # url = reverse("entity_configuration")
            # self.result = self.client.get(
            # url, data={"sub": ta_conf_data["sub"]})
        # elif self.req_counter > 5:
            # raise NotImplementedError(
            # "The mocked resposes seems to be not aligned with the correct flow"
            # )

        # if self.result.status_code != 200:
            # raise HttpError(
            # f"Something went wrong with Http Request: {self.result.__dict__}")

        # logger.info("-------------------------------------------------")
        # logger.info("")
        # return self.result_as_jws()


# class EntityResponseWithIntermediateManyHints(EntityResponse):
    # @property
    # def content(self):
        # if self.req_counter == 0:
            # self.result = self.trust_anchor_ec()
        # elif self.req_counter == 1:
            # self.result = self.rp_ec()
        # elif self.req_counter == 2:
            # sa = FederationEntityConfiguration.objects.get(
            # sub=intermediary_conf["sub"])
            # self.result = DummyContent(sa.entity_configuration_as_jws)
        # elif self.req_counter == 3:
            # self.result = DummyContent("crap")

        # elif self.req_counter == 4:
            # url = reverse("oidcfed_fetch")
            # self.result = self.client.get(
            # url,
            # data={
            # "sub": rp_onboarding_data["sub"],
            # "iss": intermediary_conf["sub"],
            # },
            # )
        # elif self.req_counter == 5:
            # url = reverse("oidcfed_fetch")
            # self.result = self.client.get(
            # url, data={"sub": intermediary_conf["sub"]})
        # elif self.req_counter == 6:
            # url = reverse("entity_configuration")
            # self.result = self.client.get(
            # url, data={"sub": ta_conf_data["sub"]})
        # elif self.req_counter > 6:
            # raise NotImplementedError(
            # "The mocked resposes seems to be not aligned with the correct flow"
            # )
        # if self.result.status_code != 200:
            # raise HttpError(
            # f"Something went wrong with Http Request: {self.result.__dict__}")

        # try:
            # return self.result_as_jws()
        # except Exception:
            # return self.result_as_it_is()
