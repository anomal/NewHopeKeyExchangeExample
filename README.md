# NewHopeKeyExchangeExample
This is an example of post-quantum key exchange using the [NewHope](https://eprint.iacr.org/2015/1092.pdf) (warning: PDF link) algorithm implemented by the Java cryptography library [Bouncy Castle](https://www.bouncycastle.org/java.html).

## Output (example)

```
Alice sends 'alicePubKey' to Bob.
alicePubKey: 1A23WMgZBEAleViQuleKTl6T/uCbloTF9T5iYG4fA2ZNUq0gIFDnQXGr7cMtExzRhw8dLPWZsJX4HaZK2hlyGGzV+4G1HsoesLcGsJ/0InohSgo6kI93+f/diJlIH1L+oTL8Jj0Fk3VHYNTcyN2qZK3QVAtRbCGdquVbCu0cq0vHkn2Up/Ml01T7eow1yyL6hOl9Yh6EwvQ+t1vcIws4BHk5aGuj2vZSsRLQFcDqfCnnZHgN+Eppm90jemBaRlVspXUunpWYGmYD6IZjaqhQcNa7L9PDtmemfObpe6p2JrhRrb6iqaibDGHX2bgqTC1FLyfFRV3PAtIBg7CN6UKuZfnYIiBg4ySPeHQfTd64ef0muGOfyVpNAMzFr4NmXixU11qKEY4ckm5uV6nhMcvnfAF4hVIwyrZD0ri54uM9w3a2SE5cAQdYuEV00IEB1F2BU1DGW4CFYiqvVZEhUBwKk2FQhelYcqLvUsOxQUQLqxqz2QQVaxkm2T1h0mP5R4DpkNecHoRBWnhIT3oUKr0zV81JSIW+rM3t3KEImoapJjWzwcSorq2d4dXaj6smxeqvtRFeHvEaamS+2wj8ItOkZe5mqhquch/LpdvDOgADg+kFKSgdH9vCFgV3HIMerpYa8E1FOZoORsHxiozmgpuj5hczyzDXPnWKOtCLprQAWQiJvvVVqYYtRZXkMsIAHgWb2ieaCGRdz9lNpoChFWlCT4pISKAXY8PubWOJ9ErVVjtOGp0HDa6/IuFvsxmBZxLODaCa4rl06GiI01EFJkhngvfwAHESblllxT9I7g3aFXxjAUizy8dmqwUMzYT3NjmDjR2Y2VhvTOkrwjxoB2iscnRSkIRvGelX3LK/vImTRRNItYMAocI2/TBPpofiidG0GUpp2cp1GO8eKkWtchm8k38jlt5P6G1rgm1QoNfoJ9Rf1HNHH9hgXkxiOw1AFOfeVuTZ7MDnJY+swb6mbQlhEKRdMw0djKDPCHvwlAvQCVu2LG05gWt+2hPdKo+VpMTB8TNpSyd7T9RXal+HhFwCvZZBAWPXfiE5j85ngc2h9p9lsElOnKxJjZSl9ayNbHCY8BxSt5lgwCc5VflV6oRdihOuS9e4A7BkmwJYu8SISqjcGfj61Un5RQV5xoUVslz/Ul3CE/zuFzXVXlVGEe0rpOYz5IYwdZhOoFIqGtFD1mBS6GxEyyh4+972h+defjahHUDbpALqEYBTgGEkAyUtZuGEb4vck9lCyRoUm2iBGY5tKu1xhR00vxpDeogsaUVyLieSGIamr2LedJtio9DpDkQd5rSmLa9Av2IrZRf/UalACvFfvkTUkm/6awgQwsJdi0mZkhJFkDSKRCkuKrkfhQardwwxE8PTV19gRdYLP7T4NGueKP2Ku4a0U1NyywFwcLHievWQ/hp+nR5SY4JouMHVFRiWG0VnyrPBWTsr3LKmMjlOc6Z8SoMkfrLL8aGP7SqfRDXiecCHQUoi69ZlWtaqWRFmmEc8aAB2/eBWrAn3R+XVYjihSheOVVR/KMDbCGp+pU6tR2rKRZOQg1ntRHo11vDbFy5Qahun+jb6X2oImGcnRDr9LEdR0NYANqbbt4sWUeBnMljoZgB3Gqs0FsEU2uxnqqM8MAvHZchjWZ1409UjbPpAHggCsy6Ci+XsBPj/LEN5FDgXNEAiw98CeitGeKCm4EerjJOsgUc4C96uaZRwJ7z8l7VXNVQHDquFzmXrBmY0YFhH2WVqOrxivRmY8In/ZwWYRdhjGxtDiSH1v7nYMUd/qIPkpTyDlFFzLi4Rc9daezhSSoDrjiqCjVSwkCZ3Fy15ExoVCttGJuUEZpzKRfSDxPpnWkCFaQTWK8kv9RF5wjGfUKpVbVEJhVYQ8OkmEcJdrlEJspQBSG3rrliz2WAbNcFVSTGNpgQ9hne802RhSw204qefgvMkDs2flKvlob775XMI2bhCleOPcoZgE+0v7mv+Cou+IxvZXqka2mfDgWTIV0WpJ6hA6F+cxk2Q8yUCahdMJEtEFmCEbacbFHrWVCXBmgI9BckMIWQ4AbzeCpNhwixcozAyy86B8IpaWBrNNbrI9lNgbT0nlvVyH/AvBoBjF5nosauWE6qR/Qd+Hi2xfKpCSNGbo3/OrT/c3nk31hqDISKh1BB3qsBrI8GaRMTVSeUBhYtI51QXkLQIjo3uopX0B1AGEfIrlBCchAalLV1wgZXpEWB2hPno1ZDwAX5bDmKbNnVOm+BjdK3uc93smjg3ggP80vKCMq1JwWny5gR5Cf1Uz1tv+XLDpazqTGB5QBMaZFhhuIeQjmtqZmI1hMtLL9Eo2cx/NxJKKZrNgwrAjYci4l3y5ZW+9WEgJoBNQ06jn7cIBLewqal3OWZCO5ukZYdQTgPL1QDDQkJo1lHm153/pGtEVIrmVCTU5E2hT1Gasval

Bob calculates shared value and value to send to Alice.
Bob calculates shared value: H31U9QWukTfFzTo1xmuNrlyYKaWuzNc8uJzlfouneAg=
Bob sends 'forAlice' to Alice.
forAlice: 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

Alice calculates shared value: H31U9QWukTfFzTo1xmuNrlyYKaWuzNc8uJzlfouneAg=

aliceSharedVal equals bobSharedVal is: true
```
