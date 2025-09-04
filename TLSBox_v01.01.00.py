#   Initial version was built in May 2025                                        #
#                                                                                #
#   Version Number Defination:                                                   #
#   v00.01.01 20250501                                                           #
#    -- -- --                                                                    #
#     |  |  |                                                                    #
#     |  |  +------     GUI Updates                                              #
#     |  +---------     Crypto Function Updates                                  #
#     +------------     Published Version (Major Change)                         #
#                                                                                #
# _______________________________________________________________________________#
#                                                                                
#   Project created in May 2025
#   01. v00.01.01 was created with basic GUI and TLS proxy functionality.
#   02. v00.02.01 was updated with logging, packet modification, and export features.
#   03. v00.03.01 Fixed the ico issue.
#   04. v01.00.00 Final release version.
#   05. v01.00.01 Fixed the Hold/modify/forward packets issue. 2025.07.30
#   06. v01.00.02 Click Modify button to display both original and modified packets. 2025.07.31
#   07. v01.01.00 Changed icon and logo
# _______________________________________________________________________________
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, filedialog
import socket
import threading
import queue
import binascii
import datetime
import time
import base64
import sys
import os
import tempfile

# === Paste your Base64 encoded PNG string here ===
# This is a placeholder. You should replace this with the actual Base64 string of your icon.
# Example (this is a tiny red square for demonstration, your actual string will be much longer):
ICON_PNG_BASE64 = """
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cGUvUmVzb3VyY2VFdmVudCMiCiAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgICB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIKICAgIHhtbG5zOkdJTVA9Imh0dHA6Ly93d3cuZ2ltcC5vcmcveG1wLyIKICAgIHhtbG5zOmlwdGNFeHQ9Imh0dHA6Ly9pcHRjLm9yZy9zdGQvSXB0YzR4bXBFeHQvMjAwOC0wMi0yOS8iCiAgICB4bWxuczpwaG90b3Nob3A9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGhvdG9zaG9wLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRvYmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgeG1wTU06RG9jdW1lbnRJRD0iZ2ltcDpkb2NpZDpnaW1wOmE4MzRhNmI1LWQyMDAtNGEzZC05NWZmLTI2ODlkNzIzOTlkMCIKICAgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDphNDczZjIyNy02MTAwLTQ3NTAtOGI4OC00NDUyMzkyOWQxOWMiCiAgIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDoxZTkwM2UyNy1jZmMwLTQ4NzAtYjE0Mi1mZTI4MjczMTQ3YTAiCiAgIGRjOkZvcm1hdD0iaW1hZ2UvcG5nIgogICBleGlmOkRhdGVUaW1lT3JpZ2luYWw9IjIwMjUtMDktMDNUMDY6Mzk6MTArMDA6MDAiCiAgIEdJTVA6QVBJPSIyLjAiCiAgIEdJTVA6UGxhdGZvcm09IldpbmRvd3MiCiAgIEdJTVA6VGltZVN0YW1wPSIxNzU2ODgxODY3NzE2MTExIgogICBHSU1QOlZlcnNpb249IjIuMTAuMzAiCiAgIGlwdGNFeHQ6RGlnaXRhbFNvdXJjZUZpbGVUeXBlPSJodHRwOi8vY3YuaXB0Yy5vcmcvbmV3c2NvZGVzL2RpZ2l0YWxzb3VyY2V0eXBlL2NvbXBvc2l0ZVdpdGhUcmFpbmVkQWxnb3JpdGhtaWNNZWRpYSIKICAgaXB0Y0V4dDpEaWdpdGFsU291cmNlVHlwZT0iaHR0cDovL2N2LmlwdGMub3JnL25ld3Njb2Rlcy9kaWdpdGFsc291cmNldHlwZS9jb21wb3NpdGVXaXRoVHJhaW5lZEFsZ29yaXRobWljTWVkaWEiCiAgIHBob3Rvc2hvcDpDcmVkaXQ9IkVkaXRlZCB3aXRoIEdvb2dsZSBBSSIKICAgcGhvdG9zaG9wOkRhdGVDcmVhdGVkPSIyMDI1LTA5LTAzVDA2OjM5OjEwKzAwOjAwIgogICB0aWZmOk9yaWVudGF0aW9uPSIxIgogICB4bXA6Q3JlYXRvclRvb2w9IkdJTVAgMi4xMCI+CiAgIDx4bXBNTTpIaXN0b3J5PgogICAgPHJkZjpTZXE+CiAgICAgPHJkZjpsaQogICAgICBzdEV2dDphY3Rpb249InNhdmVkIgogICAgICBzdEV2dDpjaGFuZ2VkPSIvIgogICAgICBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjllMmQxYTUwLTcyMWEtNDU1MC05Y2RkLTA2ZmM0ZDJiYTQ3OCIKICAgICAgc3RFdnQ6c29mdHdhcmVBZ2VudD0iR2ltcCAyLjEwIChXaW5kb3dzKSIKICAgICAgc3RFdnQ6d2hlbj0iMjAyNS0wOS0wM1QxNjo0MjoyNCIvPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDpkZmMxZjVmOC00NTIxLTQ5YzMtODA0YS03ODMzYzY4NThhMTkiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjUtMDktMDNUMTY6NDQ6MjciLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgIAo8P3hwYWNrZXQgZW5kPSJ3Ij8+7Hx8XQAAAAZiS0dEAP8A/wD/oL2nkwAAAAlwSFlzAAALEwAACxMBAJqcGAAAAAd0SU1FB+kJAwYsG1Xj84UAABAwSURBVHjarVtrryXHVV2rus/jvuaNPZkHE+IHzkx4BGLEB4QSlCgSCPGQjIIQIgSB+BX8BcTHKBACAgmBBEJIEFCcCCshTJQhBuQQA3ZsY88Qj2cmycz13HtP1158qKru6u7qc64lrnTm3jmnT3XtXfux9tq7+fy1qwIICIj/DH7Y/qXh5+p93L5H9i+ZvPb/4YfZ0qXd5/ct3d5N7UoA1H6msfDtiuwvzeFG1tx9WtfH/hkKT06vWVJQPRZGPSmUr6qymko7V+/uxPptDC7VO1dCWfkb9EvAaWDcAqPQg8PV1JLvdMeclkLEpN6Gt9y0LNfcnp2yakjtfYXjyKJ3YK/Da48RCFRQ+jEMaPR+4TqxvxSVXEClza25uwbex2MqIn2PU3FUG4U8ji6GEZJTgZh5DADAYajLTEK9GyqaqwEkqEJcnDiNsZXl92Rf5Sysq0yqDQ7PNgBPZ6+6uE8BBkHKBCeg3joWPxRIwiXXGobh+B2Tem5eVIEyF40CcGi71MjNVfR9ro8jUYN1SXkGwQQ0BH7o994PV6ngFekUHF78s5fx9nPfQcUURhkFYUygQURPYPcnT+Oxj11pZVGeugTs3z7Ai7/zDdQEXFTupvBRDhnCegiihAP6q8RDhQewAuDmgKsBVwFVHf6u0qsiqlp4z89fhF2ZwUvwEmRBMmUmYxC8AF8BlQuvtJarAFcRVUWgFg7MYxUtZmzm01ogy1axLkS5kf3HGzcSjiBQirafzjH+P2pKJix3Z3jqtx7HwUxoouCyLrFKCBYVFQRYuCa9TIAZpPD+oRm8KXO5dN/+AWqINLM8x02BMn7ZTX1mAFZRUAKgAkIgLNtQRA0STnzPHO/+7StYmeCT6SuzBAHehCYKDVhYM3mSBMha5TetJalsBenEuR5vsJQyVLKAAbYzIJyWFE4G8bcAycKRShDiyZnh4rVTOPML53CoqAR1iDCtaQiCthak8P0YdiEzrExd0Dw2DOxSTLLX3gIs+4SbWlXWmWtygeQiYW31bpIs4fGPnMfiAzs4ikEvD+8mwZQsyAfB5cMrKSYGYMsrkGLmYFE5ymEkNyNCNxUfW6+XtaeMeFLt7+yVTrGqgPf+8mX48xWa+KkYfpMZKtHgfKPDS4IxqpcDwTiUgQWr1ygzaA2edm2tw2FKUUxTyQ+7oAVkf6cIl8WpxU6Fp37zClaVgiW0+T+4Bcx65p9cKFmAcux6XKif8JFCvBoqYlybpzTIiaIkXWy5kJ0iWldo3VmdlUg4fWGJS5+4gAMzNKOicYjMsuxS4hwwBld6B/UY82UHqMmlG1BjlG1ZquuE7qdBYPCehS/Ke1z64ZM4/TOn4BWCWviNznrMAG+ZYmNwTUJKY3itoQWwXCJqTR7MlOrWhtck5MAFFC1itfIwGypGrRXAhO//6AXM3r+NAwkrIVOelRWYHS9LTBTHJIcG5qA2P2a5Mn8vIw5chwBVTBcSenm/VQYMd+88xFe/+L9d4snSWfpOVQlPPXMBq3OEZ7CEXEgpB8sY1R8bEY3KlMLaCjFb122OKtZtT+hZhSR8+Y/ewKv/fR+SQPYPURby+nLX4dqvX0JTA0feh/fz6icHTLD+Ya2zZPVr/WMRJYO62m3SaG5nGrwoYEHi2U+9gu98+6iLE0iJvIvspy5s4cIzj+DIW2tN3fUYvDfI9ZFo1eAM+u6qnvloI7cQswAncipT5LF+PZBju4rAkoS76/H3n3kZhwdNoeiP3zePRx9bYO/KVvLULm1byjKxRmAUXnkoUs9S+q9O/vxLinXIGAxkOEDrKKVk6mbtBpGlOgqYKyjh6D8O8aW/vQUZQ3Q3H3+nNOoBCWcvz2AmmBm8N/jG0DSG1cpwtBKapiuavASPUBesLL68oTGhMWEVa4b8lb/nW0hdZrWJESWW59R0QuoQ1pDJkaECsYgl0q3P3sMLl7Zw9UdO9Une9niszRohAwpNY8HQTBExCo/+1EnsOIcFHepY4zIhwQnOkCPzDqzE/hcfQFKM9uoRNsKIEkvrtwYaEGHUH7PFFdHFjMTCBRzhKDz/hzdx5tEl3nVxq0WMbfyIaC9Uv4ZVIzw89DhzatHW8nvbMzzyscsd+5XcM6MglcFptv6qQiPH4V+++l9wbwM1hWoMnmMM4JBTz3nAgRBZBQgIFYk5ghK2SOzK4Z8+8z/Yf9DEa9OGMwgdTXPlDQ+PfC8AJoCkBJK8Qd5D5iFvkJJrWXudfPws+568QU2DQxlWUIjJhdLaSWvgEqfr6PR/R8CRmJHYcg7bdHC3PJ7789fRNOrXKEJb45sJ3hsOj5peIpiIWmVwViqHpR4OWUUOwlROj449QpKA2JURefpLcLhfLrZmVNNh7hy2nMMOHfZvPMSNL9yO67Bzn6yYMhN8k9UZGK6viVd/rXXXrVRil7pf9TDhs1iMKMaFYEadC4a/HYjaMeZrgi7U/q/99V2cvbDE41dPxDUsq55izdBudnOHSQXCE1ncGrO7iqXGdAvPDbGhSgxpC1BsAGC65EIRNYgZgTmJ7WgJN37/Jm7feru1IGawupzP+xbXqz+K39GotG7xhAo1kfrNkjqr/gdq6NKfNKwnOfJTRldg5PDNEQ2IVUP84x/fxId/4zycYx9URY7/4HDVcXsG+BVAF1niQf8g0ejhMxXQe1Ae6UA3i3tnnh17PGI9bE8MjctkcNRIjaIyZlZdP8CFsD+Xg3dAI+D+Gx7XP3sHP/jhU/A+nBAhOACzmvjXr7+JO998FbOK0NEMr3xhC0tHVFmSF4QGwuFSeOIjxN6J4H4WS22SqCuH2WIJVjNsbS/wrX87gA4EuuxwmRVabW+Q0cNV7oBLKmJpi2gwT8EudodEYCHCHGFGfPcrD/HCjuHKta0WatcVMa+AU2e2MdNF2L03cXgww4IOSwA1w8ZTj0JbwI//4hzLbQ/QYbFcYLZYgHWFalZhvljAxebFf954C7eePcDpukIF1wGpQSysx424fkshD3p9sBGJvl4XihFpBXwAOsgAc0DjgdufO8DZR+fQe4TKAbOK2J4TDjX2Lp7G/hLYv30fyxhDZiTIwE6/TcPTHz+H85fmcFUd7pMjxESDk3jtpX28/Bffxm7lMKcLXaaJwFoXxxpibncGmLe8YugCI4MCqgH5mtoSwRWAmXNY+qAESXjxrx7g8hNncPJUDQfDcuZQV4T3hp2L53DH5thy94MCECxpReHqJ87h8pO7wzKwdb1UQ7/6zQe4/slv4QQDJklw2nHQKUjx4Plr15SnO4uFx4EJ++Zxn4YHZmjykkLEgsCJqsKWEdt02K4carp48l3K9CY0ZjiQ8LYZHsjjEMIRrU1RinX5zBFbdNhGhQUI54KRXfyl03j3j+1FsnM6P751e4V/+N3XsXxInKwcdlhh6YhZsgLHkSvUKrTGHcPJzkgsjJAYKO4YPSoQNYDah00HXw3mqoFFOAKVI+aK5ZUcKhNmnrEJG4ogB2ImYEGHOQDnglyP/PQuvu/p3Rb3q9TuJHDv3grPfvJ1LA+AvajIhQsItWJWBHFyRihWSwoBsSYxD74QInpm/Y5AhaCgeTSxcYsqMEQuZv4anVQVhIZqybPE3FYMkT8VRqc/tIUnPnhyBM444An3HzT4/Kdvoroj7LgKO67Cki4KH9152EfrZYFBjHMkKggL50K5a+i1uRlDQAWGTccbkMSQySfVBiCCcHCYuRDYSlW6Yhd5++kFnvzo2WCZLd3GtnmbTO3wSHj2T25Brxv2XIUdOixJzB2D2ZNwdJNDG3UOaVIEh9gGtwqEXHFKMIIf9trSpRYGo8Uw+nrFDnRLXcXpAXgB8/fNcPXnzqKi9TpywyTtvcNzf3kLB99osBcLsW3novBhaMORa/vjda9ai6MZZFCCyzoLKtCt7KWhfCSlNEIUlKqYklrYG5lnT8II1JcrXH3mDGZ11i7L3CRBdQPwpb97E/euH2Avwu4t50JMivci3cYxrnode5qzJ2RGDhWuH43GcNzOzqdHunpIMBIegJ0F3vsrZzBfMoLzQd8wpjuR+Mrn7+Dm5x60wm+7CnPGgEx2wnP9JFq9ZsJo0EVRYQqTk1NsLM2y9liXEAGMAek128CTv3YaW3scnLz6FHjl8PUb9/Ha39zHbhVPvgpmP4uxyG2aTuUUECpVpG6iPzfFk7DjLVgYv2lrjMjSNACaGfDYx09i74wbAx31a5WXXvguXvjTu63w21WFRfL5FIzBzaN767LAxveOObCgOFkynDCzyNA0AI4kfO+vnsCpd1Wxh1AAe1Gg1155iOufvouTMdhtuyS8C+mumysb7KEwKJkTIjrmpKne6dCoNO7gROE9QqV4/pkdnLtSBy5vYgBYEG6/eYTrf3AHOwppbtHmefaCuAptI2Fi0kzKssAxRlc5iMg5Tyf2J5VZYPYSSZHmj87+7BYu/MCidOS9G9275/Hsp25jeeSwHXN8lfVUEor1OVM85ClY9MWpIFg2hf5ouo45/ZmdPAAjsDJh54MzXPzRRb81VjAzE/HGSwd48id2IwUfwFmlSL40gpqyDumBh/98hAqpTEfHT25SgIr9gtTqGprSxqG0tjhqAOhR4LEP7YLR59c98UAK7/vAdseZuuJwTDtCw7aXQzQr4t+//BbmBGYK6DYVaskx6qntMvMd9dwqAqU2wGwWHhnsbUw4mhN0BKwrwUbjvAMf4ob5YGYdE3bzvjgwAxmsJpTEfV5sgwWo4Dd9LN6RudOKSC4SeqCGRi52idQbztw4GjMZjlnctRBo8bkR5jSely9PiGg0XsXecACRP2DQDjZzw8hK1L1PS/RaupscUcfPvbkFxOHMdjSnMFBWl5JgPnLCvGfKvlVw3Tnko+0ZOhpmhTIQY/anxgNPmSWycPotO5xNved5ktm26kmIhBKmPcY5cA2yjIbhlfcf1BNOKDy3MDUdJmRt2wyUqBvJ02Qjpc0CnMaJHCJyjgIVjzOWzcFwYyM0R3Hktu1K9Iut9LAW1cdbeVnRuaK1b3ZFFLFa9cv1YeIiAH7t2jWVnr1jMc+XMfbaplY8JYtDCwfe8MA8HnjDvvnQuc0HxKiNPdkpxJqAcBWZqi1H7DiHnQibZ+SIFxxBYRZOe9IkNwgfDqmbCHeRT5yT2HKhZF3lAUqDpy6zuYBiVqJG4z2JpElzC3MSM7h+tM/GDWquSSpFHk7dpAbX1NpDRaa5oJrEAg50xEzsWtebHwzZmATz1FaRmKGrGRJlNwymx6wFupiQvKzAL2ICbncnE8p5zM2hpuDl2kEmUb3o38szHHePJxUVrcih4yxr1/UFhjG93qhxjkid4pNhRPGptFZ/SWmVEjlciNLsEzAgJx/sHbfENQhkbDFKKIZYTN71lEY1mtHd/Iwghwkk118rE1t+QKXhTOY+xCK7Nn5GVv0AzT6PwNyiWCBENJoOYrZsaafZ5OIkeFOPNst5RSB/wInTkKql3FRiYzH1MHsxRkw8zld+bnAIKqRxCtyIYInxw9UcPe7OEtU8RFT5DO4w+LT7FIpGzlKM6D74P2KLzAe9v832AAAAAElFTkSuQmCC
"""

# Define a thread-safe queue for packets to be displayed in the GUI
packet_display_queue = queue.Queue()
# Define a dictionary to hold packets that are paused for modification
# Key: (connection_id, packet_direction, stream_index)
# Value: {'original_data': bytes, 'modified_data': bytes, 'event': threading.Event}
held_packets = {}
held_packets_lock = threading.Lock() # Lock for accessing held_packets dictionary

# Global counter for unique connection IDs
connection_id_counter = 0
connection_id_counter_lock = threading.Lock()

# Packet direction constants
CLIENT_TO_SERVER = "Client -> Server"
SERVER_TO_CLIENT = "Server -> Client"

class TLSSnifferApp:
    def __init__(self, master):
        self.master = master
        TLSproxy_ver = "01.01.00" # Updated version number
        TLSproxy_yr = "2025.08.04" # Updated date
        master.title("TLSBox" + " (v" + TLSproxy_ver +")" + " - " + TLSproxy_yr + " - Nigel Zhai")
        master.geometry("580x700") # Set initial window size
        master.minsize(580, 660) # Set minimum window size
        master.maxsize(580, 900)
        master.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close event

        # Set the window icon
        self.set_window_icon()

        self.running = False
        self.proxy_thread = None
        self.listen_socket = None

        # Variable for the "Hold Packets" toggle switch
        self.hold_packets_var = tk.BooleanVar(value=False) # Default to automatic forwarding

        self.create_widgets()
        self.update_gui_thread = threading.Thread(target=self.update_gui, daemon=True)
        self.update_gui_thread.start()

        # Dictionary to store packet details for the listbox
        # Key: Listbox index, Value: {'conn_id': int, 'direction': str, 'stream_index': int, 'raw_data': bytes, 'type': 'original' or 'modified'}
        self.packet_details = {}
        self.current_packet_index = 0 # Unique index for packets in the listbox

    def set_window_icon(self):
        try:
            # Decode the Base64 string
            icon_data = base64.b64decode(ICON_PNG_BASE64)

            # Attempt to use PhotoImage directly
            try:
                photo_image = tk.PhotoImage(data=icon_data)
                self.master.iconphoto(True, photo_image)
            except tk.TclError:
                # Fallback to .ico if PhotoImage fails (e.g., if the data isn't a valid PNG or Tkinter version issues)
                # This requires writing to a temporary .ico file.
                print("PhotoImage failed, attempting .ico fallback...")
                temp_ico_path = os.path.join(tempfile.gettempdir(), "temp_icon.ico")
                with open(temp_ico_path, "wb") as f:
                    f.write(icon_data) # Assuming the base64 could also be an ICO
                self.master.iconbitmap(temp_ico_path)
                os.remove(temp_ico_path) # Clean up the temporary file

        except Exception as e:
            print(f"Error setting PNG icon from Base64 or ICO fallback: {e}")
            print("Ensure the Base64 string is correct and represents a valid PNG or ICO image.")
            # Fallback to a default Tkinter icon if all else fails
            self.master.iconbitmap(default="::tk::icons::question")


    def create_widgets(self):
        # Configuration Frame
        config_frame = tk.LabelFrame(self.master, text="Configuration", padx=2, pady=5)
        config_frame.pack(pady=5, padx=2, fill="x")

        # Listen IP and Port
        tk.Label(config_frame, text="Listen IP:").grid(row=0, column=0, padx=2, pady=5, sticky="w")
        self.listen_ip_entry = tk.Entry(config_frame, width=14)
        self.listen_ip_entry.insert(0, "192.168.1.107") # Default to listen on all interfaces
        self.listen_ip_entry.grid(row=0, column=1, padx=2, pady=5, sticky="w")

        tk.Label(config_frame, text="Listen Port:").grid(row=1, column=0, padx=2, pady=5, sticky="w")
        self.listen_port_entry = tk.Entry(config_frame, width=14)
        self.listen_port_entry.insert(0, "8080") # Default port
        self.listen_port_entry.grid(row=1, column=1, padx=2, pady=5, sticky="w")

        # Target IP/Host and Port
        tk.Label(config_frame, text="Target IP/Host:").grid(row=0, column=2, padx=2, pady=5, sticky="w")
        self.target_ip_host_entry = tk.Entry(config_frame, width=14)
        self.target_ip_host_entry.insert(0, "192.168.1.107") # Default target
        self.target_ip_host_entry.grid(row=0, column=3, padx=2, pady=5, sticky="w")

        tk.Label(config_frame, text="Target Port:").grid(row=1, column=2, padx=2, pady=5, sticky="w")
        self.target_port_entry = tk.Entry(config_frame, width=14)
        self.target_port_entry.insert(0, "443") # Default target port (HTTPS)
        self.target_port_entry.grid(row=1, column=3, padx=2, pady=5, sticky="w")

        # Control Buttons and Status
        self.status_label = tk.Label(config_frame, text="Status: Stopped", fg="blue")
        self.status_label.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky="w") # Spanning more columns

        self.start_button = tk.Button(config_frame, text="Start Proxy", command=self.start_proxy, bg='#D1FFBD', fg="black")
        self.start_button.grid(row=0, column=4, columnspan=2, padx=20, pady=5, sticky="w") # Moved to next row

        self.stop_button = tk.Button(config_frame, text="Stop Proxy", command=self.stop_proxy, state=tk.DISABLED, bg='#FF5C5C', fg="black")
        self.stop_button.grid(row=1, column=4, columnspan=2, padx=20, pady=5, sticky="e") # Moved to next row


        # ========================================================================================================
        # Packet List Frame (height adjusted)
        packet_list_frame = tk.LabelFrame(self.master, text="Captured Packets", padx=5, pady=5)
        packet_list_frame.pack(pady=5, padx=5, fill="both", expand=True)

        self.packet_listbox = tk.Listbox(packet_list_frame, width=80, height=6) # Adjusted height to 12
        self.packet_listbox.pack(side="left", fill="both", expand=True)
        self.packet_listbox.bind("<<ListboxSelect>>", self.display_packet_details)

        packet_list_scrollbar = tk.Scrollbar(packet_list_frame, command=self.packet_listbox.yview)
        packet_list_scrollbar.pack(side="right", fill="y")
        self.packet_listbox.config(yscrollcommand=packet_list_scrollbar.set)

        # ========================================================================================================
        # Packet Details Frame (height adjusted)
        packet_detail_frame = tk.LabelFrame(self.master, text="Packet Details (Hex & ASCII)", padx=5, pady=5)
        packet_detail_frame.pack(pady=5, padx=5, fill="both", expand=True)

        self.packet_detail_text = scrolledtext.ScrolledText(packet_detail_frame, wrap="word", width=80, height=12, state=tk.DISABLED) # Adjusted height to 12
        self.packet_detail_text.pack(fill="both", expand=True)

        # Control Frame
        control_frame = tk.Frame(self.master, padx=5, pady=5)
        control_frame.pack(pady=5, padx=5, fill="x")

        # "Hold Packets" toggle switch
        self.hold_packets_toggle = tk.Checkbutton(
            control_frame,
            text="Hold Packets\n(Forward Manually)",
            variable=self.hold_packets_var,
            command=self.toggle_hold_packets,
            anchor="w",  # Align text to the left
            justify="left"
        )
        self.hold_packets_toggle.pack(side="left", padx=5)

        # Button width for consistency
        button_width = 12
        button_height = 2

        self.modify_button = tk.Button(control_frame, text="Modify\nSelected Packet", command=self.modify_selected_packet, state=tk.DISABLED, width=button_width, height=button_height, anchor="w")
        self.modify_button.pack(side="left", padx=5, anchor="w")

        # Forward button state now depends on the toggle
        self.forward_button = tk.Button(control_frame, text="Forward\nSelected Packet", command=self.forward_selected_packet, state=tk.DISABLED, width=button_width, height=button_height, anchor="w")
        self.forward_button.pack(side="left", padx=5, anchor="w")

        self.clear_button = tk.Button(control_frame, text="Clear Packets", command=self.clear_packets, width=button_width, height=button_height)
        self.clear_button.pack(side="right", padx=5)

        self.export_button = tk.Button(control_frame, text="Export\nSelected Packets", command=self.export_packets, width=button_width, height=button_height, bg='#FFEFB3', fg="black")
        self.export_button.pack(side="right", padx=5)


    def toggle_hold_packets(self):
        # Update the state of the forward button based on the toggle
        if self.hold_packets_var.get():
            self.forward_button.config(state=tk.NORMAL)
        else:
            self.forward_button.config(state=tk.DISABLED)
            # If turning off manual hold, release any currently held packets
            with held_packets_lock:
                for key in list(held_packets.keys()):
                    held_packets[key]['event'].set() # Release the event to unblock the forwarding thread
                held_packets.clear()


    def start_proxy(self):
        if self.running:
            messagebox.showinfo("Info", "Proxy is already running.")
            return

        try:
            listen_ip = self.listen_ip_entry.get()
            listen_port = int(self.listen_port_entry.get())
            target_ip_host = self.target_ip_host_entry.get()
            target_port = int(self.target_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers.")
            return

        if not listen_ip or not target_ip_host:
            messagebox.showerror("Error", "Please enter Listen IP and Target IP/Host.")
            return

        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text=f"Status: Listening on client [{listen_ip}:{listen_port}]. Targeting on server [{target_ip_host}:{target_port}]", fg="green")

        self.proxy_thread = threading.Thread(target=self._run_proxy_server, args=(listen_ip, listen_port, target_ip_host, target_port), daemon=True)
        self.proxy_thread.start()

    def stop_proxy(self):
        if not self.running:
            # messagebox.showinfo("Info", "Proxy is not running.")
            return

        self.running = False
        if self.listen_socket:
            try:
                self.listen_socket.shutdown(socket.SHUT_RDWR)
                self.listen_socket.close()
            except OSError as e:
                print(f"Error closing listen socket: {e}")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="blue")
        # messagebox.showinfo("Info", "Proxy stopped.")

    def _run_proxy_server(self, listen_ip, listen_port, target_ip_host, target_port):
        global connection_id_counter # Ensure we can modify the global counter
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((listen_ip, listen_port)) # Use the specified listen_ip
            self.listen_socket.listen(5)
            print(f"Proxy listening on {listen_ip}:{listen_port}...")
            print(f"Forwarding to {target_ip_host}:{target_port}")

            while self.running:
                try:
                    client_socket, client_addr = self.listen_socket.accept()
                    with connection_id_counter_lock:
                        conn_id = connection_id_counter
                        connection_id_counter += 1
                    print(f"Accepted connection {conn_id} from {client_addr[0]}:{client_addr[1]}")
                    client_handler = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_addr, target_ip_host, target_port, conn_id),
                        daemon=True
                    )
                    client_handler.start()
                except OSError as e:
                    if self.running: # Only print error if it's not due to intentional shutdown
                        print(f"Error accepting connection: {e}")
                    break # Exit loop if socket is closed or other critical error
                except Exception as e:
                    print(f"Unexpected error in proxy server loop: {e}")
                    break
        except OSError as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"Could not start proxy: {e}\n(Perhaps port {listen_port} is in use or requires elevated privileges)"))
            self.master.after(0, self.stop_proxy) # Stop the proxy if it failed to start
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", f"An unexpected error occurred: {e}"))
            self.master.after(0, self.stop_proxy)

    def _handle_client_connection(self, client_socket, client_addr, target_ip_host, target_port, conn_id):
        server_socket = None
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((target_ip_host, target_port)) # Use the target_ip_host
            print(f"Connection {conn_id}: Connected to target {target_ip_host}:{target_port}")

            # Create threads for bidirectional data forwarding
            client_to_server_thread = threading.Thread(
                target=self._forward_data,
                args=(client_socket, server_socket, CLIENT_TO_SERVER, conn_id),
                daemon=True
            )
            server_to_client_thread = threading.Thread(
                target=self._forward_data,
                args=(server_socket, client_socket, SERVER_TO_CLIENT, conn_id),
                daemon=True
            )

            client_to_server_thread.start()
            server_to_client_thread.start()

            client_to_server_thread.join() # Wait for both threads to finish
            server_to_client_thread.join()

        except Exception as e:
            print(f"Connection {conn_id}: Error handling connection: {e}")
        finally:
            if client_socket:
                client_socket.close()
            if server_socket:
                server_socket.close()
            print(f"Connection {conn_id}: Closed.")

    def _forward_data(self, source_socket, destination_socket, direction, conn_id):
        stream_index = 0
        while self.running:
            try:
                data = source_socket.recv(4096) # Read up to 4KB of data
                if not data:
                    break # Connection closed by source

                # Always add the original packet to the display queue and packet_details
                # This ensures all captured packets are logged, even if not held/modified
                self.master.after(0, lambda d=data, di=direction, ci=conn_id, si=stream_index:
                                  self._add_packet_to_display(d, di, ci, si, 'original'))

                data_to_send = data # Default to original data

                if self.hold_packets_var.get(): # Check the state of the toggle switch
                    # Prepare for holding if manual forwarding is enabled
                    packet_key = (conn_id, direction, stream_index)
                    
                    # Create an event for this packet, initially not set (meaning it's held)
                    packet_event = threading.Event()
                    with held_packets_lock:
                        held_packets[packet_key] = {
                            'original_data': data,
                            'modified_data': data, # Initially, modified data is the same as original
                            'event': packet_event
                        }
                    # Wait for the event to be set (i.e., packet is forwarded)
                    packet_event.wait() # This will block until forward_packet is called for this key

                    with held_packets_lock:
                        # Ensure the packet is still in held_packets before trying to pop
                        if packet_key in held_packets:
                            data_to_send = held_packets[packet_key]['modified_data'] # Get the (potentially modified) data
                            
                            # If modified_data is different from original_data, add the modified packet to display
                            if held_packets[packet_key]['original_data'] != data_to_send:
                                self.master.after(0, lambda d=data_to_send, di=direction, ci=conn_id, si=stream_index:
                                                  self._add_packet_to_display(d, di, ci, si, 'modified'))
                            
                            held_packets.pop(packet_key) # Remove from held_packets after forwarding
                        else:
                            # This case should ideally not happen if packet_event.wait() unblocked,
                            # but as a safeguard, if somehow it's missing, send the original data.
                            print(f"Warning: Packet {packet_key} unexpectedly not in held_packets after wait.")
                
                destination_socket.sendall(data_to_send)
                stream_index += 1 # Increment for next packet in this stream, regardless of holding

            except socket.timeout:
                continue # No data, try again
            except OSError as e:
                # Connection reset by peer, broken pipe, etc.
                print(f"Connection {conn_id} ({direction}): Socket error: {e}")
                break
            except Exception as e:
                print(f"Connection {conn_id} ({direction}): Unexpected error during forwarding: {e}")
                break

    def _add_packet_to_display(self, raw_data, direction, conn_id, stream_index, packet_type):
        """Helper function to add packet details to the GUI and internal storage."""
        display_text_prefix = ""
        if packet_type == 'original':
            display_text_prefix = "[ORIGINAL] "
        elif packet_type == 'modified':
            display_text_prefix = "[MODIFIED] "

        display_text = (
            f"[{self.current_packet_index:06d}] {display_text_prefix}"
            f"ConnID:{conn_id} | {direction} | Size:{len(raw_data)} bytes | Time:{time.strftime('%Y.%m.%d-%H:%M:%S')}"
        )
        self.packet_listbox.insert(tk.END, display_text)
        self.packet_listbox.see(tk.END) # Scroll to the end

        # Store full packet details for later retrieval
        self.packet_details[self.current_packet_index] = {
            'conn_id': conn_id,
            'direction': direction,
            'stream_index': stream_index,
            'raw_data': raw_data,
            'type': packet_type # Store the type of packet (original/modified)
        }
        self.current_packet_index += 1


    def update_gui(self):
        while True:
            try:
                packet_info = packet_display_queue.get(timeout=0.1) # Non-blocking get
                conn_id = packet_info['conn_id']
                direction = packet_info['direction']
                size = packet_info['size']
                timestamp = packet_info['timestamp']
                raw_data = packet_info['raw_data']
                stream_index = packet_info['stream_index']
                packet_type = packet_info.get('type', 'original') # Default to 'original' if not specified

                # Call the helper function to add the packet to display and storage
                self._add_packet_to_display(raw_data, direction, conn_id, stream_index, packet_type)

            except queue.Empty:
                pass # No new packets, continue checking
            except Exception as e:
                print(f"Error updating GUI: {e}")
            time.sleep(0.05) # Small delay to prevent busy-waiting

    def display_packet_details(self, event=None):
        selected_indices = self.packet_listbox.curselection()
        if not selected_indices:
            self.packet_detail_text.config(state=tk.NORMAL)
            self.packet_detail_text.delete(1.0, tk.END)
            self.packet_detail_text.config(state=tk.DISABLED)
            # Disable buttons if no packet is selected
            self.modify_button.config(state=tk.DISABLED)
            self.forward_button.config(state=tk.DISABLED)
            return

        listbox_index = selected_indices[0]
        packet_data = self.packet_details.get(listbox_index)

        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)

        if packet_data:
            raw_bytes = packet_data['raw_data']
            hex_dump = binascii.hexlify(raw_bytes).decode('ascii')
            ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])

            formatted_output = ""
            for i in range(0, len(hex_dump), 32): # 16 bytes per line (32 hex chars)
                hex_part = hex_dump[i:i+32]
                ascii_part = ascii_dump[i//2 : i//2 + 16]
                formatted_output += f"{hex_part:<32}  {ascii_part}\n"

            self.packet_detail_text.insert(tk.END, formatted_output)
            # Enable modify button when a packet is selected
            self.modify_button.config(state=tk.NORMAL)
            # Enable forward button only if "Hold Packets" toggle is active
            # and the selected packet is an 'original' type that is currently held
            if self.hold_packets_var.get():
                packet_key = (packet_data['conn_id'], packet_data['direction'], packet_data['stream_index'])
                with held_packets_lock:
                    if packet_key in held_packets and packet_data['type'] == 'original':
                        self.forward_button.config(state=tk.NORMAL)
                    else:
                        self.forward_button.config(state=tk.DISABLED)
            else:
                self.forward_button.config(state=tk.DISABLED)
        else:
            self.modify_button.config(state=tk.DISABLED)
            self.forward_button.config(state=tk.DISABLED)

        self.packet_detail_text.config(state=tk.DISABLED)

    def get_selected_packet_key(self):
        selected_indices = self.packet_listbox.curselection()
        if not selected_indices:
            return None, None # Return None for key and listbox_index
        listbox_index = selected_indices[0]
        packet_info = self.packet_details.get(listbox_index)
        if packet_info and packet_info['type'] == 'original': # Only allow modifying original packets
            return (packet_info['conn_id'], packet_info['direction'], packet_info['stream_index']), listbox_index
        return None, None

    def modify_selected_packet(self):
        packet_key, listbox_index = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No original packet selected to modify, or selected packet is already a modified version.")
            return

        with held_packets_lock:
            if packet_key not in held_packets:
                messagebox.showwarning("Warning", "Selected packet is not currently held. It might have already been forwarded or 'Hold Packets' is not enabled.")
                return

            current_data = held_packets[packet_key]['modified_data'] # Get the current (possibly already modified) data
            current_hex = binascii.hexlify(current_data).decode('ascii')

            modified_hex = simpledialog.askstring(
                "Modify Packet Data",
                "Enter new packet data in hexadecimal (e.g., 48656C6C6F):\n"
                "(Warning: Incorrect hex may break the connection!)",
                initialvalue=current_hex,
                parent=self.master
            )

            if modified_hex is not None:
                try:
                    new_data = binascii.unhexlify(modified_hex)
                    held_packets[packet_key]['modified_data'] = new_data # Update the modified data in held_packets
                    messagebox.showinfo("Success", "Packet data modified. Remember to forward it.")
                    
                    # No need to refresh display immediately here, as the modified packet will be displayed
                    # when it's actually forwarded.
                    # The original packet in self.packet_details should remain as the original.
                    
                except binascii.Error:
                    messagebox.showerror("Error", "Invalid hexadecimal input. Please enter only valid hex characters (0-9, a-f, A-F).")
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred during modification: {e}")

    def forward_selected_packet(self):
        packet_key, listbox_index = self.get_selected_packet_key()
        if not packet_key:
            messagebox.showwarning("Warning", "No original packet selected to forward.")
            return

        if not self.hold_packets_var.get():
            messagebox.showinfo("Info", "Automatic forwarding is enabled. Packets are sent immediately.")
            return

        with held_packets_lock:
            if packet_key in held_packets:
                # Set the event to release the packet
                held_packets[packet_key]['event'].set()
                # The _forward_data function will now handle adding the modified packet to display
                # if it was indeed modified.
            else:
                messagebox.showwarning("Warning", "Selected packet is not currently held or has already been forwarded.")


    def clear_packets(self):
        self.packet_listbox.delete(0, tk.END)
        self.packet_detail_text.config(state=tk.NORMAL)
        self.packet_detail_text.delete(1.0, tk.END)
        self.packet_detail_text.config(state=tk.DISABLED)
        self.packet_details.clear()
        self.current_packet_index = 0
        self.modify_button.config(state=tk.DISABLED)
        # Ensure forward button state reflects the toggle
        if self.hold_packets_var.get():
            self.forward_button.config(state=tk.NORMAL)
        else:
            self.forward_button.config(state=tk.DISABLED)

        with held_packets_lock:
            for key in list(held_packets.keys()):
                held_packets[key]['event'].set() # Release any held packets
            held_packets.clear()
        # messagebox.showinfo("Cleared", "All displayed and held packets cleared.")

    def export_packets(self):
        if not self.packet_details:
            messagebox.showinfo("Info", "No packets to export.")
            return

        now = datetime.datetime.now()
        current_datetime_str = now.strftime("%Y%m%d_%H%M%S") # Format: YYYYMMDD_HHMMSS

        file_path = filedialog.asksaveasfilename(
            defaultextension=".log", # Corrected: only the extension here
            initialfile=f"TLS_log_{current_datetime_str}.log", # Added initialfile
            filetypes=[("Log Files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path:
            return # User cancelled

        try:
            with open(file_path, 'w') as f: # Open the file here
                f.write(f"===========================================================\n")
                f.write(f"TLS Sniffer Export - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Exported {len(self.packet_details)} packets:\n")
                f.write(f"Listen IP/Port: [{self.listen_ip_entry.get()} : {self.listen_port_entry.get()}]\n")
                f.write(f"Target IP/Port: [{self.target_ip_host_entry.get()} : {self.target_port_entry.get()}]\n")
                f.write(f"===========================================================\n\n\n")

                for listbox_index in sorted(self.packet_details.keys()):
                    packet_info = self.packet_details[listbox_index]
                    conn_id = packet_info['conn_id']
                    direction = packet_info['direction']
                    stream_index = packet_info['stream_index']
                    raw_bytes = packet_info['raw_data']
                    packet_type = packet_info.get('type', 'original') # Get packet type

                    f.write(f"--- Packet [{listbox_index:06d}] ({packet_type.upper()}) ---------------------------------------\n")
                    f.write(f"Connection ID: {conn_id}\n")
                    f.write(f"Direction: {direction}\n")
                    f.write(f"Stream Index: {stream_index}\n")
                    f.write(f"Size: {len(raw_bytes)} bytes\n\n")

                    # Hex Dump
                    f.write("Hexadecimal:\n")
                    hex_dump = binascii.hexlify(raw_bytes).decode('ascii')
                    for i in range(0, len(hex_dump), 32): # 16 bytes per line (32 hex chars)
                        hex_part = hex_dump[i:i+32]
                        f.write(f"{hex_part}\n")
                    f.write("\n")

                    # ASCII Dump
                    f.write("ASCII:\n")
                    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])
                    for i in range(0, len(ascii_dump), 16): # 16 chars per line
                        ascii_part = ascii_dump[i:i+16]
                        f.write(f"{ascii_part}\n")
                    f.write("\n")
            messagebox.showinfo("Success", f"Packets exported successfully to {file_path}") # This line should be outside the `with` block to ensure `f` is closed before showing info.
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export packets: {e}")


    def on_closing(self):
        self.stop_proxy()
        self.master.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = TLSSnifferApp(root)
    # root.iconbitmap('logo.ico')
    root.mainloop()
