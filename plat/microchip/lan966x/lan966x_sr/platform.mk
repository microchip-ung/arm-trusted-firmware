include plat/microchip/lan966x/common/common.mk

$(eval $(call add_define,LAN966X_TZ))
$(eval $(call add_define_val,FC_DEFAULT,FLEXCOM0))