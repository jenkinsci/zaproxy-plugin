package fr.novia.zaproxyplugin;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.AbstractDescribableImpl;

import java.io.Serializable;

import org.kohsuke.stapler.DataBoundConstructor;

public class ZAPuser extends AbstractDescribableImpl<ZAPuser> implements Serializable {
	
	private final int contextId;
	private final int userId;
	
	@DataBoundConstructor
	public ZAPuser(int contextId, int userId) {
		this.contextId = contextId;
		this.userId = userId;
	}
	
	public int getContextId() {
		return contextId;
	}
	
	public int getUserId() {
		return userId;
	}

	@Override
	public String toString() {
		return "ZAPuser [contextId=" + contextId + ", userId=" + userId + "]";
	}
	
	@Extension
	public static class ZAPuserDescriptorImpl extends Descriptor<ZAPuser> {

		@Override
		public String getDisplayName() {
			// TODO Auto-generated method stub
			return null;
		}
		
	}

}
